rule TTP_XOR_QUAD_CurrentVersionRun_3a5f {
  strings:
    $key_3a5f = { 69 30 [2] 4d 3e [2] 66 12 [2] 48 30 [2] 5c 2b [2] 53 31 [2] 4d 2c [2] 4f 2d [2] 54 2b [2] 48 2c [2] 54 03 }

  condition:
    any of them
}