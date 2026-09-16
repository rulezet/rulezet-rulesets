rule TTP_XOR_QUAD_CurrentVersionRun_255f {
  strings:
    $key_255f = { 76 30 [2] 52 3e [2] 79 12 [2] 57 30 [2] 43 2b [2] 4c 31 [2] 52 2c [2] 50 2d [2] 4b 2b [2] 57 2c [2] 4b 03 }

  condition:
    any of them
}