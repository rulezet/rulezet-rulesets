rule _20160921_61ffae07802bf5013fbbf8f137c827c3_20160921_d999dcba53f5_2095 {
  meta:
    description = "datamaliciousorder - from files 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "{return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(" ascii
    $s2 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){" ascii
    $s3 = "{return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = " \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(fun" ascii
    $s5 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s6 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})()" ascii
    $s7 = "o\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s8 = "})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s9 = ")(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}