rule TTP_XOR_QUAD_CurrentVersionRun_075f {
  strings:
    $key_075f = { 54 30 [2] 70 3e [2] 5b 12 [2] 75 30 [2] 61 2b [2] 6e 31 [2] 70 2c [2] 72 2d [2] 69 2b [2] 75 2c [2] 69 03 }

  condition:
    any of them
}