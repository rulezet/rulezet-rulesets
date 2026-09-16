rule TTP_XOR_QUAD_CurrentVersionRun_6f65 {
  strings:
    $key_6f65 = { 3c 0a [2] 18 04 [2] 33 28 [2] 1d 0a [2] 09 11 [2] 06 0b [2] 18 16 [2] 1a 17 [2] 01 11 [2] 1d 16 [2] 01 39 }

  condition:
    any of them
}