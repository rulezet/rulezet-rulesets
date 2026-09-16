rule TTP_XOR_QUAD_CurrentVersionRun_2f41 {
  strings:
    $key_2f41 = { 7c 2e [2] 58 20 [2] 73 0c [2] 5d 2e [2] 49 35 [2] 46 2f [2] 58 32 [2] 5a 33 [2] 41 35 [2] 5d 32 [2] 41 1d }

  condition:
    any of them
}