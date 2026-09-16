rule TTP_XOR_QUAD_CurrentVersionRun_3141 {
  strings:
    $key_3141 = { 62 2e [2] 46 20 [2] 6d 0c [2] 43 2e [2] 57 35 [2] 58 2f [2] 46 32 [2] 44 33 [2] 5f 35 [2] 43 32 [2] 5f 1d }

  condition:
    any of them
}