rule TTP_XOR_QUAD_CurrentVersionRun_0c5f {
  strings:
    $key_0c5f = { 5f 30 [2] 7b 3e [2] 50 12 [2] 7e 30 [2] 6a 2b [2] 65 31 [2] 7b 2c [2] 79 2d [2] 62 2b [2] 7e 2c [2] 62 03 }

  condition:
    any of them
}