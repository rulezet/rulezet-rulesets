rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_5c9dd9a0e8a8_4341 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash3       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s2 = "turn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s3 = ",(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s4 = ";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s5 = "n \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}