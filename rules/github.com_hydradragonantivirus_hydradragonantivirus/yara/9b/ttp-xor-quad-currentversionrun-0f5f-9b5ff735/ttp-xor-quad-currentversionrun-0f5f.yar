rule TTP_XOR_QUAD_CurrentVersionRun_0f5f {
  strings:
    $key_0f5f = { 5c 30 [2] 78 3e [2] 53 12 [2] 7d 30 [2] 69 2b [2] 66 31 [2] 78 2c [2] 7a 2d [2] 61 2b [2] 7d 2c [2] 61 03 }

  condition:
    any of them
}