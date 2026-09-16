rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_5_2_Virus_Hijac_244 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d08c7f4e1036eb1580a255e16a8cf72c8fa4b374b3ab7545267dcd8d3a8a9fae"
    hash2       = "d779e1b9b965342481f87fc756c097f891ad2a68cc697dba97e17a3eff5524b9"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2  = "re=\"X86\" name=\"OINFOP12.EXE\" type=\"win32\"></assemblyIdentity><description>OInfo</description><dependency><dependentAssembl" ascii
    $s3  = "Created by MIDL version 6.00.0361 at Thu Oct 26 19:46:58 2006" fullword ascii
    $s4  = "CurVer = s 'OfficeObj.OfficeObj12.1'" fullword ascii
    $s5  = "OInfoS 12 1.0 Type Library" fullword ascii
    $s6  = "IOfficeObj12 Interface" fullword ascii
    $s7  = ":Office Data Provider for WBE" fullword wide
    $s8  = "OfficeObj.OfficeObj12.1 = s 'OfficeObj12 Class'" fullword ascii
    $s9  = "OfficeObj.OfficeObj12 = s 'OfficeObj12 Class'" fullword ascii
    $s10 = "ForceRemove {DBF82DC7-E750-4ccf-B09C-D8AECEF7158E} = s 'OfficeObj12 Class'" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}