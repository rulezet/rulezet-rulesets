rule sig_20170427_a2ad7fc45827068fa402cac361b5a0d9 {
  meta:
    description = "datamaliciousorder - file 20170427_a2ad7fc45827068fa402cac361b5a0d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01193cdbbb45cbd57815b109b06e048c758bdc3809282fcab0137e59b654f605"

  strings:
    $s1 = "function aKNArRyEzwDSUiJ(xTYAUsRaOCBMemW, KQHAcBbviISkYTusxzD) { " fullword ascii
    $s2 = "if (wDPUGjnLMRTpBOJtfu() == false) {" fullword ascii
    $s3 = "return xTYAUsRaOCBMemW.split(KQHAcBbviISkYTusxzD).join(\"\"); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}