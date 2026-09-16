rule Virus_Infector_Win32_Expiro_Gen_7_102_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af62d4b052f0cedeeca30e8dca38db34ed85b9b00159ed0833e0b36f3404e280"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentI8=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentI8=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}