rule TTP_XOR_QUAD_CurrentVersionRun_5749 {
  strings:
    $key_5749 = { 04 26 [2] 20 28 [2] 0b 04 [2] 25 26 [2] 31 3d [2] 3e 27 [2] 20 3a [2] 22 3b [2] 39 3d [2] 25 3a [2] 39 15 }

  condition:
    any of them
}