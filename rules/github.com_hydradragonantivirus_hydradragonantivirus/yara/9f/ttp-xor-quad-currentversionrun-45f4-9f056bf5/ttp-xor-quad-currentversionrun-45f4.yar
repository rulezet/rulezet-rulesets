rule TTP_XOR_QUAD_CurrentVersionRun_45f4 {
  strings:
    $key_45f4 = { 16 9b [2] 32 95 [2] 19 b9 [2] 37 9b [2] 23 80 [2] 2c 9a [2] 32 87 [2] 30 86 [2] 2b 80 [2] 37 87 [2] 2b a8 }

  condition:
    any of them
}