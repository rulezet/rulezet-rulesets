rule TTP_XOR_QUAD_CurrentVersionRun_6b5f {
  strings:
    $key_6b5f = { 38 30 [2] 1c 3e [2] 37 12 [2] 19 30 [2] 0d 2b [2] 02 31 [2] 1c 2c [2] 1e 2d [2] 05 2b [2] 19 2c [2] 05 03 }

  condition:
    any of them
}