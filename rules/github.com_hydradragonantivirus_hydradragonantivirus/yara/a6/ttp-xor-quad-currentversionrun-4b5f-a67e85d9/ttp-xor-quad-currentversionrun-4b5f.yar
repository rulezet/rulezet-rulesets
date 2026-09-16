rule TTP_XOR_QUAD_CurrentVersionRun_4b5f {
  strings:
    $key_4b5f = { 18 30 [2] 3c 3e [2] 17 12 [2] 39 30 [2] 2d 2b [2] 22 31 [2] 3c 2c [2] 3e 2d [2] 25 2b [2] 39 2c [2] 25 03 }

  condition:
    any of them
}