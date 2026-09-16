rule TTP_XOR_QUAD_CurrentVersionRun_6fe4 {
  strings:
    $key_6fe4 = { 3c 8b [2] 18 85 [2] 33 a9 [2] 1d 8b [2] 09 90 [2] 06 8a [2] 18 97 [2] 1a 96 [2] 01 90 [2] 1d 97 [2] 01 b8 }

  condition:
    any of them
}