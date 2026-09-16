rule TTP_XOR_QUAD_CurrentVersionRun_f3f5 {
  strings:
    $key_f3f5 = { a0 9a [2] 84 94 [2] af b8 [2] 81 9a [2] 95 81 [2] 9a 9b [2] 84 86 [2] 86 87 [2] 9d 81 [2] 81 86 [2] 9d a9 }

  condition:
    any of them
}