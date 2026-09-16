rule TTP_XOR_QUAD_CurrentVersionRun_505f {
  strings:
    $key_505f = { 03 30 [2] 27 3e [2] 0c 12 [2] 22 30 [2] 36 2b [2] 39 31 [2] 27 2c [2] 25 2d [2] 3e 2b [2] 22 2c [2] 3e 03 }

  condition:
    any of them
}