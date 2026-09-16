rule _20160921_91af5c220d1ea27d72d05f472ba8fa16_20160921_c42fb5c75aea_5545 {
  meta:
    description = "datamaliciousorder - from files 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash5       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "\"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(functio" ascii
    $s2 = "n fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s3 = "(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";" ascii
    $s4 = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s5 = "{return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}