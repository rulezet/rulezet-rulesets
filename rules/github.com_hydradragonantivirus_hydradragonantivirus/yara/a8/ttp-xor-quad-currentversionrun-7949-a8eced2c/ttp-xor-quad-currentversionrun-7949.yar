rule TTP_XOR_QUAD_CurrentVersionRun_7949 {
  strings:
    $key_7949 = { 2a 26 [2] 0e 28 [2] 25 04 [2] 0b 26 [2] 1f 3d [2] 10 27 [2] 0e 3a [2] 0c 3b [2] 17 3d [2] 0b 3a [2] 17 15 }

  condition:
    any of them
}