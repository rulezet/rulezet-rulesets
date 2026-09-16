rule TTP_XOR_QUAD_CurrentVersionRun_0df5 {
  strings:
    $key_0df5 = { 5e 9a [2] 7a 94 [2] 51 b8 [2] 7f 9a [2] 6b 81 [2] 64 9b [2] 7a 86 [2] 78 87 [2] 63 81 [2] 7f 86 [2] 63 a9 }

  condition:
    any of them
}