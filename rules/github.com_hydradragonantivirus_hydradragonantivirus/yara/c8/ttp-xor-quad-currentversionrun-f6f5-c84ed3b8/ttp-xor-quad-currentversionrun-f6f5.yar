rule TTP_XOR_QUAD_CurrentVersionRun_f6f5 {
  strings:
    $key_f6f5 = { a5 9a [2] 81 94 [2] aa b8 [2] 84 9a [2] 90 81 [2] 9f 9b [2] 81 86 [2] 83 87 [2] 98 81 [2] 84 86 [2] 98 a9 }

  condition:
    any of them
}