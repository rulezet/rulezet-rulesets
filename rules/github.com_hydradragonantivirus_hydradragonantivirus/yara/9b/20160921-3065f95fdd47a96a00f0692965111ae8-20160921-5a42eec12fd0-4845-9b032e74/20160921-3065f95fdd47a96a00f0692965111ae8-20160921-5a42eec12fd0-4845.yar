rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_5a42eec12fd0_4845 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash3       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"

  strings:
    $s1 = "n \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(f" ascii
    $s2 = "function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s3 = "GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(funct" ascii
    $s4 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s5 = "(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}