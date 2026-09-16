rule _20160921_02b826231ece268e91633311d2c70554_20160921_570295874dae_4140 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = " f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OU" ascii
    $s2 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYs\";})(),(function f000" ascii
    $s3 = " f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "urn \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s5 = "urn \"KXg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}