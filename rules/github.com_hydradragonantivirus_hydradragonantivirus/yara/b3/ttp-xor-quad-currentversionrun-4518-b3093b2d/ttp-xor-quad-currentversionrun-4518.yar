rule TTP_XOR_QUAD_CurrentVersionRun_4518 {
  strings:
    $key_4518 = { 16 77 [2] 32 79 [2] 19 55 [2] 37 77 [2] 23 6c [2] 2c 76 [2] 32 6b [2] 30 6a [2] 2b 6c [2] 37 6b [2] 2b 44 }

  condition:
    any of them
}