rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_2_2_Virus_Hijac_139 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "838086ed8b4207c84b7c179a283d8cfe128e7e3c50a0073d96c26764f782742d"
    hash2       = "25580ea287f391443b3f34e0d22069b5b1739b6312c794f7f97a82c0c4488470"

  strings:
    $s1  = "|47675|UI_STATS|Minesweeper Statistics - %1//statistics dialog title (with username)" fullword wide
    $s2  = "Executable for Minesweeper Game" fullword wide
    $s3  = "|57833|UI_STATS|Minesweeper Statistics//statistics dialog title (no username)" fullword wide
    $s4  = "<description>Minesweeper</description>" fullword ascii
    $s5  = "No version exists in save game -- creating new" fullword wide
    $s6  = "|54922|ACC|Minesweeper//accessibility root node name" fullword wide
    $s7  = "|55891|ACC|Row %1!d!, Column %2!d! Tile (Cleared). %3!d! Mine(s) Surrounding.//accessibility description" fullword wide
    $s8  = "|55018|ACC|Row %1!d!, Column %2!d! Tile (Concealed).//accessibility description" fullword wide
    $s9  = "|57058|ACC|Row %1!d!, Column %2!d! Tile (Concealed and Flagged).//accessibility description" fullword wide
    $s10 = "|43121|ACC|Row %1!d!, Column %2!d! Tile (Concealed with Question Mark).//accessibility description" fullword wide
    $s11 = "|51167|ACC|Row %1!d!, Column %2!d! Tile (Cleared). No Mines Surrounding.//accessibility description" fullword wide
    $s12 = "|51718|ACC|Status information//accessibility description" fullword wide
    $s13 = "|43727|ACC|Mines remaining: %1//accessibility mines remaining description" fullword wide
    $s14 = "|43410|ACC|Time elapsed: %1//accessibility time elapsed description" fullword wide
    $s15 = "already have dimensions: %d x %d" fullword wide
    $s16 = "Unexpected value returned from getAdjMineCount" fullword wide
    $s17 = "Too many high scores for dialog" fullword wide
    $s18 = "|44981|CLA_UI_dialog|Game Lost// dialog for losing" fullword wide
    $s19 = "|43236|CLA_UI_dialog|Game Won// dialog for winning" fullword wide
    $s20 = "Scanbar animation complete" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}