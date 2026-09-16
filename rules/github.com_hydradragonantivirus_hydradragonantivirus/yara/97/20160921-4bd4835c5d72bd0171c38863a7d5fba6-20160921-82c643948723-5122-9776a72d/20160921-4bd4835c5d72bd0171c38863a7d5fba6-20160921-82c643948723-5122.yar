rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_82c643948723_5122 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash3       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash4       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash5       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash6       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(" ascii
    $s2 = "k(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\"" ascii
    $s3 = "Ui\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s4 = "Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s5 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}