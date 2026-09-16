rule TTP_XOR_QUAD_CurrentVersionRun_5951 {
  strings:
    $key_5951 = { 0a 3e [2] 2e 30 [2] 05 1c [2] 2b 3e [2] 3f 25 [2] 30 3f [2] 2e 22 [2] 2c 23 [2] 37 25 [2] 2b 22 [2] 37 0d }

  condition:
    any of them
}