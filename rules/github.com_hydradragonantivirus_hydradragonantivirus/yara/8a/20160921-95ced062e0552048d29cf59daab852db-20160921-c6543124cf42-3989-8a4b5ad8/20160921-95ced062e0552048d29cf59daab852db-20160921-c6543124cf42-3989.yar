rule _20160921_95ced062e0552048d29cf59daab852db_20160921_c6543124cf42_3989 {
  meta:
    description = "datamaliciousorder - from files 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash4       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"
    hash5       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s2 = ")(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s3 = "f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp" ascii
    $s4 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){retu" ascii
    $s5 = "turn \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6 = "e\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}