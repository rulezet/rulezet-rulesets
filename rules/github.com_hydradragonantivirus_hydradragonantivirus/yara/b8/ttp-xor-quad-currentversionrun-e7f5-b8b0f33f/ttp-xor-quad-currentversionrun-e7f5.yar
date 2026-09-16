rule TTP_XOR_QUAD_CurrentVersionRun_e7f5 {
  strings:
    $key_e7f5 = { b4 9a [2] 90 94 [2] bb b8 [2] 95 9a [2] 81 81 [2] 8e 9b [2] 90 86 [2] 92 87 [2] 89 81 [2] 95 86 [2] 89 a9 }

  condition:
    any of them
}