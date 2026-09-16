rule TTP_XOR_QUAD_CurrentVersionRun_285f {
  strings:
    $key_285f = { 7b 30 [2] 5f 3e [2] 74 12 [2] 5a 30 [2] 4e 2b [2] 41 31 [2] 5f 2c [2] 5d 2d [2] 46 2b [2] 5a 2c [2] 46 03 }

  condition:
    any of them
}