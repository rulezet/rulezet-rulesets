rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_8753c13c904d_5160 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_8753c13c904d4c1e9e4a848591336ee8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"

  strings:
    $s1 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2 = "uck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s3 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = ";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s5 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}