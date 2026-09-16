import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113_1_Virus_Hija_238 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d1b509451f00201266d1ca734cf8ae37fdeeedde7a1a4550e0750e9e3316a8"
    hash2       = "c39ed073ecc4cb372eedb12da81184d440c6eb2e2be1e3fc8b731ad43355717e"
    hash3       = "906c9e4e5ab33e9c806bf6d599c20c12a923b135167ae404a119876bfdae42ab"

  strings:
    $x1  = "  = Module: C:\\Windows\\system32\\wuapi.dll" fullword ascii
    $x2  = "  = Process: C:\\Windows\\system32\\wusa.exe" fullword ascii
    $s3  = "Attempting to create remote handler process as admin-PC\\admin in session 1" fullword ascii
    $s4  = "Installing self-contained with source=C:\\Windows\\SoftwareDistribution\\Download\\3113c6d599a3a2b1ecafecbe68cc9745\\Windows6.1-" ascii
    $s5  = "Generating request for CBS update 185F8E51-DDE4-40EE-BE6D-19929CC5C173 in sandbox C:\\Windows\\SoftwareDistribution\\Download\\3" ascii
    $s6  = "  - Added scan package service, ServiceID = {B5572015-EE42-40D0-A6DB-FE7E47754898} Third party service" fullword ascii
    $s7  = "--  END  --  COMAPI: Install [ClientId = Windows Defender]" fullword ascii
    $s8  = ">>--  RESUMED  -- COMAPI: Install [ClientId = Windows Defender]" fullword ascii
    $s9  = "  - ServiceName = Windows Update " fullword ascii
    $s10 = "Validating signature for C:\\Windows\\SoftwareDistribution\\Download\\3113c6d599a3a2b1ecafecbe68cc9745_ctc\\Windows6.1-KB3118401" ascii
    $s11 = "  - ServiceID = {B5572015-EE42-40D0-A6DB-FE7E47754898} Third party service" fullword ascii
    $s12 = "Installing self-contained with source=C:\\Windows\\SoftwareDistribution\\Download\\3113c6d599a3a2b1ecafecbe68cc9745\\Windows6.1-" ascii
    $s13 = "Validating signature for C:\\Windows\\SoftwareDistribution\\ScanFile\\b5572015-ee42-40d0-a6db-fe7e47754898\\Source.cab:" fullword ascii
    $s14 = "  * Computer Brand = Xen" fullword ascii
    $s15 = "  * Computer Model = HVM domU" fullword ascii
    $s16 = "Validating signature for C:\\Windows\\SoftwareDistribution\\Download\\3113c6d599a3a2b1ecafecbe68cc9745_ctc\\Windows6.1-KB3118401" ascii
    $s17 = "Generating request for CBS update 185F8E51-DDE4-40EE-BE6D-19929CC5C173 in sandbox C:\\Windows\\SoftwareDistribution\\Download\\3" ascii
    $s18 = "  * ServiceID = {B5572015-EE42-40D0-A6DB-FE7E47754898} Third party service" fullword ascii
    $s19 = "***********  DnldMgr: Copy update to cache [UpdateId = {185F8E51-DDE4-40EE-BE6D-19929CC5C173}.501]  ***********" fullword ascii
    $s20 = "===========  Logging initialized (build: 7.5.7601.17514, tz: +0800)  ===========" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}