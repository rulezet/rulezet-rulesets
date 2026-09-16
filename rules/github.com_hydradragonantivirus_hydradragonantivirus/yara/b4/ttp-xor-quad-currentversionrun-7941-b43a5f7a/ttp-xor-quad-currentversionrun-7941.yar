rule TTP_XOR_QUAD_CurrentVersionRun_7941 {
  strings:
    $key_7941 = { 2a 2e [2] 0e 20 [2] 25 0c [2] 0b 2e [2] 1f 35 [2] 10 2f [2] 0e 32 [2] 0c 33 [2] 17 35 [2] 0b 32 [2] 17 1d }

  condition:
    any of them
}