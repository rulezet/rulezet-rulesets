rule TTP_XOR_QUAD_CurrentVersionRun_0b5f {
  strings:
    $key_0b5f = { 58 30 [2] 7c 3e [2] 57 12 [2] 79 30 [2] 6d 2b [2] 62 31 [2] 7c 2c [2] 7e 2d [2] 65 2b [2] 79 2c [2] 65 03 }

  condition:
    any of them
}