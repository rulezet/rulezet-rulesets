rule TTP_XOR_QUAD_CurrentVersionRun_4008 {
  strings:
    $key_4008 = { 13 67 [2] 37 69 [2] 1c 45 [2] 32 67 [2] 26 7c [2] 29 66 [2] 37 7b [2] 35 7a [2] 2e 7c [2] 32 7b [2] 2e 54 }

  condition:
    any of them
}