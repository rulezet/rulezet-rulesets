rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_3065f95fdd47_3432 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash3       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash4       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash5       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "urn \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(f" ascii
    $s2 = ",(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){" ascii
    $s3 = "fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZW" ascii
    $s4 = "(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";}" ascii
    $s5 = " \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(funct" ascii
    $s6 = "})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}