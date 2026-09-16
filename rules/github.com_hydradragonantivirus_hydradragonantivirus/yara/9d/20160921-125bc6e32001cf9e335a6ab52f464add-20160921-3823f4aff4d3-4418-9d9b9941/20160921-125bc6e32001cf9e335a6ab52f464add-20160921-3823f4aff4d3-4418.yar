rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_3823f4aff4d3_4418 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_af22e174703ebae0fa1368fd471dba37.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash3       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash4       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"
    hash5       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash6       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = " \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s2 = " \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";" ascii
    $s4 = "fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OP" ascii
    $s5 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}