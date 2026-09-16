rule TTP_XOR_QUAD_CurrentVersionRun_6ae4 {
  strings:
    $key_6ae4 = { 39 8b [2] 1d 85 [2] 36 a9 [2] 18 8b [2] 0c 90 [2] 03 8a [2] 1d 97 [2] 1f 96 [2] 04 90 [2] 18 97 [2] 04 b8 }

  condition:
    any of them
}