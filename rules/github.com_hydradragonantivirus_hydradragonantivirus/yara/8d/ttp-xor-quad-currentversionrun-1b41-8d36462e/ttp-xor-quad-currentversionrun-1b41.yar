rule TTP_XOR_QUAD_CurrentVersionRun_1b41 {
  strings:
    $key_1b41 = { 48 2e [2] 6c 20 [2] 47 0c [2] 69 2e [2] 7d 35 [2] 72 2f [2] 6c 32 [2] 6e 33 [2] 75 35 [2] 69 32 [2] 75 1d }

  condition:
    any of them
}