rule TTP_XOR_QUAD_CurrentVersionRun_4508 {
  strings:
    $key_4508 = { 16 67 [2] 32 69 [2] 19 45 [2] 37 67 [2] 23 7c [2] 2c 66 [2] 32 7b [2] 30 7a [2] 2b 7c [2] 37 7b [2] 2b 54 }

  condition:
    any of them
}