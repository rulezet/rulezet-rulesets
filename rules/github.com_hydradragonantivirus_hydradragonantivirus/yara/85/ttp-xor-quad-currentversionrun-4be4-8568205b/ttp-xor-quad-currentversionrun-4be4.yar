rule TTP_XOR_QUAD_CurrentVersionRun_4be4 {
  strings:
    $key_4be4 = { 18 8b [2] 3c 85 [2] 17 a9 [2] 39 8b [2] 2d 90 [2] 22 8a [2] 3c 97 [2] 3e 96 [2] 25 90 [2] 39 97 [2] 25 b8 }

  condition:
    any of them
}