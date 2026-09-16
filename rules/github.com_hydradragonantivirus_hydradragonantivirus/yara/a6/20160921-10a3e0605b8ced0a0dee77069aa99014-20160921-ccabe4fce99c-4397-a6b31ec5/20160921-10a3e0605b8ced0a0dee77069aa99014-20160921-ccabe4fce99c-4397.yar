rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_ccabe4fce99c_4397 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = "(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})" ascii
    $s2 = "0(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm" ascii
    $s3 = "function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s4 = "rn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ug\";})(),(fu" ascii
    $s5 = "\"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}