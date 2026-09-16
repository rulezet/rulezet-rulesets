rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_2eacd3ef1ce6_3451 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_95ced062e0552048d29cf59daab852db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"

  strings:
    $s1 = " f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJ" ascii
    $s2 = "n \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s3 = "ction f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s4 = " f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"D" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh" ascii
    $s6 = "{return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}