rule TTP_XOR_QUAD_CurrentVersionRun_5e4f {
  strings:
    $key_5e4f = { 0d 20 [2] 29 2e [2] 02 02 [2] 2c 20 [2] 38 3b [2] 37 21 [2] 29 3c [2] 2b 3d [2] 30 3b [2] 2c 3c [2] 30 13 }

  condition:
    any of them
}