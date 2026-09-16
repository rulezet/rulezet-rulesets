rule TTP_XOR_QUAD_CurrentVersionRun_4708 {
  strings:
    $key_4708 = { 14 67 [2] 30 69 [2] 1b 45 [2] 35 67 [2] 21 7c [2] 2e 66 [2] 30 7b [2] 32 7a [2] 29 7c [2] 35 7b [2] 29 54 }

  condition:
    any of them
}