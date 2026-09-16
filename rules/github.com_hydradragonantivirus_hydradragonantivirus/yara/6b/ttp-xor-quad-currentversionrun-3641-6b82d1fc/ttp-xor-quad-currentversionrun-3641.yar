rule TTP_XOR_QUAD_CurrentVersionRun_3641 {
  strings:
    $key_3641 = { 65 2e [2] 41 20 [2] 6a 0c [2] 44 2e [2] 50 35 [2] 5f 2f [2] 41 32 [2] 43 33 [2] 58 35 [2] 44 32 [2] 58 1d }

  condition:
    any of them
}