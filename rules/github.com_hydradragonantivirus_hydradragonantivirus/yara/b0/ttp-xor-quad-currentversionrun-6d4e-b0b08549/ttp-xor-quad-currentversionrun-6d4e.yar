rule TTP_XOR_QUAD_CurrentVersionRun_6d4e {
  strings:
    $key_6d4e = { 3e 21 [2] 1a 2f [2] 31 03 [2] 1f 21 [2] 0b 3a [2] 04 20 [2] 1a 3d [2] 18 3c [2] 03 3a [2] 1f 3d [2] 03 12 }

  condition:
    any of them
}