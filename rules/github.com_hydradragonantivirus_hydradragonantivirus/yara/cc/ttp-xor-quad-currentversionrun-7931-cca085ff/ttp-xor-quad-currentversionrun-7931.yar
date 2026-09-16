rule TTP_XOR_QUAD_CurrentVersionRun_7931 {
  strings:
    $key_7931 = { 2a 5e [2] 0e 50 [2] 25 7c [2] 0b 5e [2] 1f 45 [2] 10 5f [2] 0e 42 [2] 0c 43 [2] 17 45 [2] 0b 42 [2] 17 6d }

  condition:
    any of them
}