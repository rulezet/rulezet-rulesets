rule TTP_XOR_QUAD_CurrentVersionRun_0af5 {
  strings:
    $key_0af5 = { 59 9a [2] 7d 94 [2] 56 b8 [2] 78 9a [2] 6c 81 [2] 63 9b [2] 7d 86 [2] 7f 87 [2] 64 81 [2] 78 86 [2] 64 a9 }

  condition:
    any of them
}