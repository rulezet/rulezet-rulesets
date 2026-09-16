import "pe"
rule _Virus_Autorun_Gen_Heur_Mint_Zard_39_1_Virus_Autorun_Gen_Heur_Mi_4 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Heur.Mint.Zard.39_1.vir, Virus.Autorun_Gen.Heur.Mint.Zard.39_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a2e4c49adf05cb8e2b1afcf316a207c4cda0a4388fe937aa46c1ecfed47eeeb"
    hash2       = "e46997cb6a5db994426214c78fc25955035311e5ce7bb0ac4a958d3b44524989"

  strings:
    $s1  = "Enter the e-mail addresses of users in the Read and Change boxes (example: 'someone@example.com'). Separate names with a semicol" ascii
    $s2  = "Enter the e-mail addresses of users in the Read and Change boxes (example: 'someone@example.com'). Separate names with a semicol" ascii
    $s3  = "experienced a serious problem with the '|1' add-in. This add-in is incompatible with Data Execution Prevention mode and should b" ascii
    $s4  = "Online Meeting feature requires Microsoft NetMeeting 2.11 or later. You can either install it by running IE5Setup.exe from the I" ascii
    $s5  = "experienced a serious problem with the '|1' add-in. This add-in is incompatible with Data Execution Prevention mode and should b" ascii
    $s6  = "Starting MSINFO32.EXE" fullword ascii
    $s7  = "E5 folder located on your CD, or download it from https://www.microsoft.com/netmeeting/." fullword ascii
    $s8  = "Install Microsoft PDF and XPS add-ins from Office.com" fullword ascii
    $s9  = "The Microsoft PDF and XPS export add-ins are not installed correctly. You can get the most recent components from Office.com." fullword ascii
    $s10 = "both encrypted and password protected. The Office Open XML Formats available in Office 2007 and later provide stronger encryptio" ascii
    $s11 = "Information Rights Management (IRM) in Microsoft Office helps prevent sensitive documents and e-mail messages from being forward" ascii
    $s12 = "have credentials for this service. Would you like to get credentials for this service now? " fullword ascii
    $s13 = "+Change box (example: 'someone@example.com'). Separate names with a semicolon(;). To select names from the Address book, click t" ascii
    $s14 = "both encrypted and password protected. The Office Open XML Formats available in Office 2007 and later provide stronger encryptio" ascii
    $s15 = "This |0 was created with restricted permission using the Information Rights Management service for Microsoft Office. You do not " ascii
    $s16 = "+Change box (example: 'someone@example.com'). Separate names with a semicolon(;). To select names from the Address book, click t" ascii
    $s17 = "ext that identifies the target of the URL. " fullword ascii
    $s18 = "Choose Manual mode to have full control over where to apply styles by using the Target Rule drop-down.$" fullword ascii
    $s19 = "long or non-linear sequence or steps in a task, process, or workflow. Works best with Level 1 text only. Maximizes both horizont" ascii
    $s20 = "Process`T" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3eafac78b2f94eb6a014af9c2a27809" and (8 of them)
    ) or (all of them)
}