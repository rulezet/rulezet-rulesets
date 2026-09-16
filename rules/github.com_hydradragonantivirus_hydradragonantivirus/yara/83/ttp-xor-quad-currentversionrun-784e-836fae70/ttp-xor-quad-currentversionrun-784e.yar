rule TTP_XOR_QUAD_CurrentVersionRun_784e {
  strings:
    $key_784e = { 2b 21 [2] 0f 2f [2] 24 03 [2] 0a 21 [2] 1e 3a [2] 11 20 [2] 0f 3d [2] 0d 3c [2] 16 3a [2] 0a 3d [2] 16 12 }

  condition:
    any of them
}