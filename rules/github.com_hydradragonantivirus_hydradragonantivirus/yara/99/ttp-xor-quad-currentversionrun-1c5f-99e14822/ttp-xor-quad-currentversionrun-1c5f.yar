rule TTP_XOR_QUAD_CurrentVersionRun_1c5f {
  strings:
    $key_1c5f = { 4f 30 [2] 6b 3e [2] 40 12 [2] 6e 30 [2] 7a 2b [2] 75 31 [2] 6b 2c [2] 69 2d [2] 72 2b [2] 6e 2c [2] 72 03 }

  condition:
    any of them
}