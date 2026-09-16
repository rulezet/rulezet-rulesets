rule TTP_XOR_QUAD_CurrentVersionRun_0ae4 {
  strings:
    $key_0ae4 = { 59 8b [2] 7d 85 [2] 56 a9 [2] 78 8b [2] 6c 90 [2] 63 8a [2] 7d 97 [2] 7f 96 [2] 64 90 [2] 78 97 [2] 64 b8 }

  condition:
    any of them
}