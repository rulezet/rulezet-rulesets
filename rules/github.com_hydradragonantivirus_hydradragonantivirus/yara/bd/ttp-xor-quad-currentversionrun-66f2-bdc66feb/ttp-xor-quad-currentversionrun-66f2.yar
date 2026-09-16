rule TTP_XOR_QUAD_CurrentVersionRun_66f2 {
  strings:
    $key_66f2 = { 35 9d [2] 11 93 [2] 3a bf [2] 14 9d [2] 00 86 [2] 0f 9c [2] 11 81 [2] 13 80 [2] 08 86 [2] 14 81 [2] 08 ae }

  condition:
    any of them
}