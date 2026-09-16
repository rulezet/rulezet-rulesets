rule TTP_XOR_QUAD_CurrentVersionRun_3e59 {
  strings:
    $key_3e59 = { 6d 36 [2] 49 38 [2] 62 14 [2] 4c 36 [2] 58 2d [2] 57 37 [2] 49 2a [2] 4b 2b [2] 50 2d [2] 4c 2a [2] 50 05 }

  condition:
    any of them
}