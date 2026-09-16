rule TTP_XOR_QUAD_CurrentVersionRun_6931 {
  strings:
    $key_6931 = { 3a 5e [2] 1e 50 [2] 35 7c [2] 1b 5e [2] 0f 45 [2] 00 5f [2] 1e 42 [2] 1c 43 [2] 07 45 [2] 1b 42 [2] 07 6d }

  condition:
    any of them
}