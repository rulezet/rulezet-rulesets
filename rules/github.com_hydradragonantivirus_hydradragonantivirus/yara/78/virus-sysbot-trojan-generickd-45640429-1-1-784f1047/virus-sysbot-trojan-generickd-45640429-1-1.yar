rule Virus_Sysbot_Trojan_GenericKD_45640429_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.45640429_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e134a6c799de4a4705eebb7fd139c9c1b1f0a2e8b527e732ee7a40fdc5f49ee4"

  strings:
    $s1  = "login Successfully!" fullword wide
    $s2  = "Clocky - Manage your time" fullword wide
    $s3  = "' and Password = '" fullword wide
    $s4  = "Please Enter Same Password!" fullword wide
    $s5  = "insert into UserTB (Name, Email, Birthday, Password) values ('" fullword wide
    $s6  = "select * from UserTB where Name LIKE '" fullword wide
    $s7  = "select * from UserTB where Name = '" fullword wide
    $s8  = "Get started with Clocky" fullword wide
    $s9  = "SELECT * FROM TimeSheet ORDER BY TSID DESC" fullword wide
    $s10 = "SELECT * FROM TimeSheet WHERE TSID not in (SELECT TOP (SELECT COUNT(1)-5 FROM TimeSheet) TSID FROM TimeSheet)" fullword wide
    $s11 = "SELECT * FROM ProjectTB" fullword wide
    $s12 = "SELECT * FROM TimeSheet where ProjectName = '" fullword wide
    $s13 = "SELECT * FROM TimeSheet where CreateDate = '" fullword wide
    $s14 = "SELECT * FROM WorkspacesTB" fullword wide
    $s15 = "&Account" fullword wide
    $s16 = "Do you have'nt account?" fullword wide
    $s17 = "Create a  account to start tracking time and supercharge your productivity." fullword wide
    $s18 = "Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=Clocky;Data Source=." fullword wide
    $s19 = "Roboto Light" fullword wide
    $s20 = "SELECT WName FROM WorkspacesTB WHERE UID = '" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}