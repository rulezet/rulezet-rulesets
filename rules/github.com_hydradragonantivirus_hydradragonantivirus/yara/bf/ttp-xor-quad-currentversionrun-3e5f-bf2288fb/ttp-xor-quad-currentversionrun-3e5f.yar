rule TTP_XOR_QUAD_CurrentVersionRun_3e5f {
  strings:
    $key_3e5f = { 6d 30 [2] 49 3e [2] 62 12 [2] 4c 30 [2] 58 2b [2] 57 31 [2] 49 2c [2] 4b 2d [2] 50 2b [2] 4c 2c [2] 50 03 }

  condition:
    any of them
}