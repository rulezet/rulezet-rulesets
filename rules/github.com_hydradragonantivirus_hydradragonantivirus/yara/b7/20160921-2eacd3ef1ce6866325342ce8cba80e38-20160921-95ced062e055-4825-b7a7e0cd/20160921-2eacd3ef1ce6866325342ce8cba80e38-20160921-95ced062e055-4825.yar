rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_95ced062e055_4825 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash3       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = " f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb" ascii
    $s2 = "ion f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return " ascii
    $s3 = "return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(" ascii
    $s4 = "tion f000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s5 = "\"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}