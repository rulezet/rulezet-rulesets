rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_1_Virus_Danger_Win32_Wo_94 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_16_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash2       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash3       = "49a22cf6e0b0bb0719ea71eaf4ddc13a1d9cfafe3de6dc8500db73676c71d120"
    hash4       = "34e2a6e460e8c621b808310b38123fee90c86ea6bd2901186eb28bb6d46779c2"
    hash5       = "c35804a74edf23b99ba415d32b56dcd2dec5a0332ea141327e02895dc66e5872"
    hash6       = "58df3c604e68ae72afda237905fca3f890c4271bcdba6b0b4db5b6c510a84bf0"

  strings:
    $s1  = "create table resources(rid integer not null primary key autoincrement, url text(512) not null unique, state integer not null def" ascii
    $s2  = "select rid, url, state, lastsynchronized, ttl, skiphours, skipdays, synchpriority, synchretries, flags, contentsize, cursyncetag" ascii
    $s3  = "ency><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" process" ascii
    $s4  = "Invalid output stream passed to CSMBConnection::doProtocolDownload" fullword ascii
    $s5  = "%d subscription has an update.An error occurred while synchronizing comments" fullword wide
    $s6  = "e integer default 0, cursyncetag text(128), cursynclastmodified text(128) default NULL, cursynccontentsize integer default -1, c" ascii
    $s7  = ".An error occurred while synchronizing commentsXNo Review Tracker alerts for the last %s " fullword wide
    $s8  = "Mozilla/3.0 (compatible; Acrobat Annots 8.0)" fullword ascii
    $s9  = "Error occurred while reading SMB resource: " fullword ascii
    $s10 = "Error stepping prepared statement" fullword ascii
    $s11 = "%d subscriptions have updates" fullword wide
    $s12 = "%d subscription updated" fullword wide
    $s13 = "Within the last %s:" fullword wide
    $s14 = "file must be opened in PR_RDWR or PR_WRONLY to perform this operation" fullword ascii
    $s15 = "insert into resources(url, state, lastsynchronized, ttl, skiphours, skipdays, synchpriority, synchretries, flags, contentsize, c" ascii
    $s16 = " skipdays integer default 0, synchpriority integer not null, synchretries integer default 0, flags integer default 0, contentsiz" ascii
    $s17 = ", cursynclastmodified, cursynccontentsize, cursynctotalsynced, responsecode from resources where synchpriority< 50 and state !=0" ascii
    $s18 = "select rid, url, state, lastsynchronized, ttl, skiphours, skipdays, synchpriority, synchretries, flags, contentsize, cursyncetag" ascii
    $s19 = ", cursynclastmodified, cursynccontentsize, cursynctotalsynced, responsecode from resources where synchpriority >= 50 and state !" ascii
    $s20 = "ault 0, lastsynchronized integer default 0, ttl integer not null, ttloverride integer default null, skiphours integer default 0," ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}