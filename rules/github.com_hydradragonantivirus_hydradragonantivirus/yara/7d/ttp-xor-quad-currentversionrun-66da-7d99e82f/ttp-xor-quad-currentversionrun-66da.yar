rule TTP_XOR_QUAD_CurrentVersionRun_66da {
  strings:
    $key_66da = { 35 b5 [2] 11 bb [2] 3a 97 [2] 14 b5 [2] 00 ae [2] 0f b4 [2] 11 a9 [2] 13 a8 [2] 08 ae [2] 14 a9 [2] 08 86 }

  condition:
    any of them
}