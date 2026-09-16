rule TTP_XOR_QUAD_CurrentVersionRun_7b41 {
  strings:
    $key_7b41 = { 28 2e [2] 0c 20 [2] 27 0c [2] 09 2e [2] 1d 35 [2] 12 2f [2] 0c 32 [2] 0e 33 [2] 15 35 [2] 09 32 [2] 15 1d }

  condition:
    any of them
}