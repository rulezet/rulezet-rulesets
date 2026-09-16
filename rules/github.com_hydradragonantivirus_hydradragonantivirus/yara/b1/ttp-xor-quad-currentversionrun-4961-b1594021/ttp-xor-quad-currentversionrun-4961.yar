rule TTP_XOR_QUAD_CurrentVersionRun_4961 {
  strings:
    $key_4961 = { 1a 0e [2] 3e 00 [2] 15 2c [2] 3b 0e [2] 2f 15 [2] 20 0f [2] 3e 12 [2] 3c 13 [2] 27 15 [2] 3b 12 [2] 27 3d }

  condition:
    any of them
}