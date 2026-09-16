rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_f926399cbb63_4996 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s2 = "rn \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s3 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";}" ascii
    $s4 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZWu\";})(),(fun" ascii
    $s5 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}