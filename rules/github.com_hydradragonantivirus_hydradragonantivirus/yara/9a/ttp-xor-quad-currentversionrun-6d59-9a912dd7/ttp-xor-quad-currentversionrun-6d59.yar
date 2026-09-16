rule TTP_XOR_QUAD_CurrentVersionRun_6d59 {
  strings:
    $key_6d59 = { 3e 36 [2] 1a 38 [2] 31 14 [2] 1f 36 [2] 0b 2d [2] 04 37 [2] 1a 2a [2] 18 2b [2] 03 2d [2] 1f 2a [2] 03 05 }

  condition:
    any of them
}