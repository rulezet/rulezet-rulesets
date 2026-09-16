rule TTP_XOR_QUAD_CurrentVersionRun_7971 {
  strings:
    $key_7971 = { 2a 1e [2] 0e 10 [2] 25 3c [2] 0b 1e [2] 1f 05 [2] 10 1f [2] 0e 02 [2] 0c 03 [2] 17 05 [2] 0b 02 [2] 17 2d }

  condition:
    any of them
}