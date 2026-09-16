rule TTP_XOR_QUAD_CurrentVersionRun_2141 {
  strings:
    $key_2141 = { 72 2e [2] 56 20 [2] 7d 0c [2] 53 2e [2] 47 35 [2] 48 2f [2] 56 32 [2] 54 33 [2] 4f 35 [2] 53 32 [2] 4f 1d }

  condition:
    any of them
}