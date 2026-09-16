rule TTP_XOR_QUAD_CurrentVersionRun_1f5f {
  strings:
    $key_1f5f = { 4c 30 [2] 68 3e [2] 43 12 [2] 6d 30 [2] 79 2b [2] 76 31 [2] 68 2c [2] 6a 2d [2] 71 2b [2] 6d 2c [2] 71 03 }

  condition:
    any of them
}