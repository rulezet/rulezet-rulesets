rule TTP_XOR_QUAD_CurrentVersionRun_45e8 {
  strings:
    $key_45e8 = { 16 87 [2] 32 89 [2] 19 a5 [2] 37 87 [2] 23 9c [2] 2c 86 [2] 32 9b [2] 30 9a [2] 2b 9c [2] 37 9b [2] 2b b4 }

  condition:
    any of them
}