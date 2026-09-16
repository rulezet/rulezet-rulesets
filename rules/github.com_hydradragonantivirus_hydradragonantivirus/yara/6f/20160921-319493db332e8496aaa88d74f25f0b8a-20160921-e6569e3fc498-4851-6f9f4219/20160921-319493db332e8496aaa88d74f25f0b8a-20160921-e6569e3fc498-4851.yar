rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_e6569e3fc498_4851 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "ction f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return " ascii
    $s3 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return " ascii
    $s4 = "(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";}" ascii
    $s5 = ")(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}