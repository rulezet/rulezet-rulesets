import "pe"
rule _Virus_Autorun_Gen_Heur_Mint_Autorunner_1_Virus_Hijack_Gen_Troja_157 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Heur.Mint.Autorunner.1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefdc6da05cfd4012097251989683d30f21626362c29463da121dc621046b2b6"
    hash2       = "940de455f281b3225827ecddd883f1b43ba1368dbd7f57716d0a339045f24379"

  strings:
    $s1  = "StatisticsDialog::CreateListEntry() - Failed to create list entry for string %s" fullword wide
    $s2  = "|60010|SOL_STATS|Solitaire Statistics - %1//statistics dialog title (with username)" fullword wide
    $s3  = "StatisticsDialog::Show() - Unable to load the menu image" fullword wide
    $s4  = "BuildAPurbleGame::FormatScore() - Unable to get the currency symbol" fullword wide
    $s5  = "BuildAPurbleGame::FormatScore() - Unable to get the positive number style" fullword wide
    $s6  = "StatisticsDialog::CreateListEntry() - Unable to localize string %s" fullword wide
    $s7  = "Executable for Solitaire Game" fullword wide
    $s8  = "SolitaireGame::OnTimePenalty() - Std Scoring: Subtract penalty delta(%d) from score of %d" fullword wide
    $s9  = "SolitaireGame::OnUndoMove() - Std Scoring: Subtract penalty delta(%d) from score of %d" fullword wide
    $s10 = "SolitaireGame::OnUndoMove() - Un-Timed Scoring: Subtract penalty delta(%d) from score of %d" fullword wide
    $s11 = "SolitaireGame::OnGoneThruDeck() - Std Scoring: Subtract penalty delta(%d) from score of %d" fullword wide
    $s12 = "SolitaireGame::OnGoneThruDeck() - Un-Timed Scoring: Subtract penalty delta(%d) from score of %d" fullword wide
    $s13 = "SolitaireGame::OnCardDragStarted() - Card should belong to stack named %s, not %s" fullword wide
    $s14 = "OptionsDialog::SetCardDrawNum() - Invalid card draw mode %d" fullword wide
    $s15 = "|60011|SOL_STATS|Solitaire Statistics//statistics dialog title (no username)" fullword wide
    $s16 = "|62724|SOL_STATS|Best Sessions// The heading for the high score entries in vegas mode." fullword wide
    $s17 = "SolitaireStatistics::FromXml() - NULL source xml." fullword wide
    $s18 = "SolitaireStatistics::FromXml() - Incorrect number of score entries" fullword wide
    $s19 = "SolitaireStatistics::FromXml() - Incorrect number of date entries" fullword wide
    $s20 = "SolitaireStatistics::ToXml() - NULL parent tag." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "01392ca861cf87b8d28ad9ea90016bb4" and (8 of them)
    ) or (all of them)
}