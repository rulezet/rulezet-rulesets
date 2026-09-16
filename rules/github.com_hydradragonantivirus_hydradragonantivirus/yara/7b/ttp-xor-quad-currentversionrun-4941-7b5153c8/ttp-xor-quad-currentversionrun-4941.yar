rule TTP_XOR_QUAD_CurrentVersionRun_4941 {
  strings:
    $key_4941 = { 1a 2e [2] 3e 20 [2] 15 0c [2] 3b 2e [2] 2f 35 [2] 20 2f [2] 3e 32 [2] 3c 33 [2] 27 35 [2] 3b 32 [2] 27 1d }

  condition:
    any of them
}