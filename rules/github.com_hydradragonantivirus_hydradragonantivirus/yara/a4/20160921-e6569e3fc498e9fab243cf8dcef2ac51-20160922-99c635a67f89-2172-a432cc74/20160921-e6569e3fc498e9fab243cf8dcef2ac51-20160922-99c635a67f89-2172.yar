rule _20160921_e6569e3fc498e9fab243cf8dcef2ac51_20160922_99c635a67f89_2172 {
  meta:
    description = "datamaliciousorder - from files 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = ";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f0" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = ";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s4 = "b\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s5 = "eturn \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})()," ascii
    $s6 = "tion f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s7 = ";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f0" ascii
    $s8 = "tion f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s9 = "ion f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}