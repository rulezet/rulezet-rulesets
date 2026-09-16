rule TTP_XOR_QUAD_CurrentVersionRun_4ee4 {
  strings:
    $key_4ee4 = { 1d 8b [2] 39 85 [2] 12 a9 [2] 3c 8b [2] 28 90 [2] 27 8a [2] 39 97 [2] 3b 96 [2] 20 90 [2] 3c 97 [2] 20 b8 }

  condition:
    any of them
}