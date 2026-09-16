rule _20160921_95ced062e0552048d29cf59daab852db_20160921_c6543124cf42_1513 {
  meta:
    description = "datamaliciousorder - from files 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash4       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash5       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash6       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1  = "(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";" ascii
    $s2  = "turn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(" ascii
    $s3  = "a\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4  = " f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv" ascii
    $s5  = "0(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s6  = "tion f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f000(){return" ascii
    $s7  = "(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){r" ascii
    $s8  = "\"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s9  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s10 = "})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s11 = "\"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s12 = "(),(function f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s13 = "unction f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}