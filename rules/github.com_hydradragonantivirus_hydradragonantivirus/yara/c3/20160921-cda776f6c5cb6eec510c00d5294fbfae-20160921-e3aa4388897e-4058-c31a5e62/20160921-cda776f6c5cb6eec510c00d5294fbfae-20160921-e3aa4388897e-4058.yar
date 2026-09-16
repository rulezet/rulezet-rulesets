rule _20160921_cda776f6c5cb6eec510c00d5294fbfae_20160921_e3aa4388897e_4058 {
  meta:
    description = "datamaliciousorder - from files 20160921_cda776f6c5cb6eec510c00d5294fbfae.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"
    hash2       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = "ction fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s2 = ",(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){" ascii
    $s3 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s4 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck" ascii
    $s5 = "(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s6 = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}