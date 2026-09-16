rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_5f040a1454ca_5044 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash3       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"

  strings:
    $s1 = "{return \"XHj\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s2 = "})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Xg\";" ascii
    $s5 = "i\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}