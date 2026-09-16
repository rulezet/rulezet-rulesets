rule TTP_XOR_QUAD_CurrentVersionRun_5efd {
  strings:
    $key_5efd = { 0d 92 [2] 29 9c [2] 02 b0 [2] 2c 92 [2] 38 89 [2] 37 93 [2] 29 8e [2] 2b 8f [2] 30 89 [2] 2c 8e [2] 30 a1 }

  condition:
    any of them
}