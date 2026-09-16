rule TTP_XOR_QUAD_CurrentVersionRun_6c41 {
  strings:
    $key_6c41 = { 3f 2e [2] 1b 20 [2] 30 0c [2] 1e 2e [2] 0a 35 [2] 05 2f [2] 1b 32 [2] 19 33 [2] 02 35 [2] 1e 32 [2] 02 1d }

  condition:
    any of them
}