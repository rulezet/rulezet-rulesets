rule TTP_XOR_QUAD_CurrentVersionRun_6865 {
  strings:
    $key_6865 = { 3b 0a [2] 1f 04 [2] 34 28 [2] 1a 0a [2] 0e 11 [2] 01 0b [2] 1f 16 [2] 1d 17 [2] 06 11 [2] 1a 16 [2] 06 39 }

  condition:
    any of them
}