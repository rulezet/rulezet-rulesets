rule TTP_XOR_QUAD_CurrentVersionRun_669c {
  strings:
    $key_669c = { 35 f3 [2] 11 fd [2] 3a d1 [2] 14 f3 [2] 00 e8 [2] 0f f2 [2] 11 ef [2] 13 ee [2] 08 e8 [2] 14 ef [2] 08 c0 }

  condition:
    any of them
}