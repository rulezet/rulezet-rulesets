rule TTP_XOR_QUAD_CurrentVersionRun_4e5f {
  strings:
    $key_4e5f = { 1d 30 [2] 39 3e [2] 12 12 [2] 3c 30 [2] 28 2b [2] 27 31 [2] 39 2c [2] 3b 2d [2] 20 2b [2] 3c 2c [2] 20 03 }

  condition:
    any of them
}