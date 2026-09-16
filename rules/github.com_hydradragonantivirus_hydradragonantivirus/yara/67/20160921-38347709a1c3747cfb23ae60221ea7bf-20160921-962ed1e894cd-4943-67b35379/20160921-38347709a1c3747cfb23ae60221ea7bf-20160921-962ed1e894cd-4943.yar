rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_962ed1e894cd_4943 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash3       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "k(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";" ascii
    $s2 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s3 = "(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck()" ascii
    $s4 = "{return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})" ascii
    $s5 = "Pu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}