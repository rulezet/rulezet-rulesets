rule TTP_XOR_QUAD_CurrentVersionRun_784d {
  strings:
    $key_784d = { 2b 22 [2] 0f 2c [2] 24 00 [2] 0a 22 [2] 1e 39 [2] 11 23 [2] 0f 3e [2] 0d 3f [2] 16 39 [2] 0a 3e [2] 16 11 }

  condition:
    any of them
}