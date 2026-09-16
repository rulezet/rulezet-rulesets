rule _20160921_570295874daef65ccf11d909395ae377_20160921_5d6863feab41_5214 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "nction f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s2 = "on f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s3 = "on f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s4 = "{return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii
    $s5 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}