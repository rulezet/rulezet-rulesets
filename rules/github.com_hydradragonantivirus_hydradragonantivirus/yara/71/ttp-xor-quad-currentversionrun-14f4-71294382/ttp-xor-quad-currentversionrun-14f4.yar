rule TTP_XOR_QUAD_CurrentVersionRun_14f4 {
  strings:
    $key_14f4 = { 47 9b [2] 63 95 [2] 48 b9 [2] 66 9b [2] 72 80 [2] 7d 9a [2] 63 87 [2] 61 86 [2] 7a 80 [2] 66 87 [2] 7a a8 }

  condition:
    any of them
}