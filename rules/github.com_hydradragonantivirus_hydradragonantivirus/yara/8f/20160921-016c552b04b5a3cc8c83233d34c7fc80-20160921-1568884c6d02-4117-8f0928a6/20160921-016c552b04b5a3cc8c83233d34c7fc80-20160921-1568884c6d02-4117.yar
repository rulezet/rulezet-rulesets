rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1568884c6d02_4117 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash5       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash6       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "urn \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s2 = "\"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s3 = "ion f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s5 = "ion f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}