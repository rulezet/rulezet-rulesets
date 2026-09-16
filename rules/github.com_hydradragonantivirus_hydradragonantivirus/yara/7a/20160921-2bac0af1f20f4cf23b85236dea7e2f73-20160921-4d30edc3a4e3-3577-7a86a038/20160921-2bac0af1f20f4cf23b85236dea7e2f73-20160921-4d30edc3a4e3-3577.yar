rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_4d30edc3a4e3_3577 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"

  strings:
    $s1 = "(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s2 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s3 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s4 = "(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";}" ascii
    $s5 = "IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s6 = "uck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}