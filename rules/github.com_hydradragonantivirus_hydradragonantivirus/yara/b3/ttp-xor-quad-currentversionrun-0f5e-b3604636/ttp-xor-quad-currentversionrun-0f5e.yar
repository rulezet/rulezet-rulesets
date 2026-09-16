rule TTP_XOR_QUAD_CurrentVersionRun_0f5e {
  strings:
    $key_0f5e = { 5c 31 [2] 78 3f [2] 53 13 [2] 7d 31 [2] 69 2a [2] 66 30 [2] 78 2d [2] 7a 2c [2] 61 2a [2] 7d 2d [2] 61 02 }

  condition:
    any of them
}