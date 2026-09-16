rule TTP_XOR_QUAD_CurrentVersionRun_3fe4 {
  strings:
    $key_3fe4 = { 6c 8b [2] 48 85 [2] 63 a9 [2] 4d 8b [2] 59 90 [2] 56 8a [2] 48 97 [2] 4a 96 [2] 51 90 [2] 4d 97 [2] 51 b8 }

  condition:
    any of them
}