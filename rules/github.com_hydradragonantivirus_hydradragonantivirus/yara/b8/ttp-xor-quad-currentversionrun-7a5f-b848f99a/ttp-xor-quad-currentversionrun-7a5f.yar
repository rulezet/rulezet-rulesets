rule TTP_XOR_QUAD_CurrentVersionRun_7a5f {
  strings:
    $key_7a5f = { 29 30 [2] 0d 3e [2] 26 12 [2] 08 30 [2] 1c 2b [2] 13 31 [2] 0d 2c [2] 0f 2d [2] 14 2b [2] 08 2c [2] 14 03 }

  condition:
    any of them
}