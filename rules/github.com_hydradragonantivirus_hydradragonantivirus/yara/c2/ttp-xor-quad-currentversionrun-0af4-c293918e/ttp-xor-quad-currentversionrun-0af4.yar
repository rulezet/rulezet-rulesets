rule TTP_XOR_QUAD_CurrentVersionRun_0af4 {
  strings:
    $key_0af4 = { 59 9b [2] 7d 95 [2] 56 b9 [2] 78 9b [2] 6c 80 [2] 63 9a [2] 7d 87 [2] 7f 86 [2] 64 80 [2] 78 87 [2] 64 a8 }

  condition:
    any of them
}