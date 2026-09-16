rule TTP_XOR_QUAD_CurrentVersionRun_7c31 {
  strings:
    $key_7c31 = { 2f 5e [2] 0b 50 [2] 20 7c [2] 0e 5e [2] 1a 45 [2] 15 5f [2] 0b 42 [2] 09 43 [2] 12 45 [2] 0e 42 [2] 12 6d }

  condition:
    any of them
}