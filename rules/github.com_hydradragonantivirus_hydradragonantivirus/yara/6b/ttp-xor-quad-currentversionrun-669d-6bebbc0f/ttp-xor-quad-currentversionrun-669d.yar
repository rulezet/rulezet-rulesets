rule TTP_XOR_QUAD_CurrentVersionRun_669d {
  strings:
    $key_669d = { 35 f2 [2] 11 fc [2] 3a d0 [2] 14 f2 [2] 00 e9 [2] 0f f3 [2] 11 ee [2] 13 ef [2] 08 e9 [2] 14 ee [2] 08 c1 }

  condition:
    any of them
}