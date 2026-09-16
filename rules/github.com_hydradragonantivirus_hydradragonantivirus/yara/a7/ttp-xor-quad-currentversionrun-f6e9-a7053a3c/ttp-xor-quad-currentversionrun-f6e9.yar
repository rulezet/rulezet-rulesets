rule TTP_XOR_QUAD_CurrentVersionRun_f6e9 {
  strings:
    $key_f6e9 = { a5 86 [2] 81 88 [2] aa a4 [2] 84 86 [2] 90 9d [2] 9f 87 [2] 81 9a [2] 83 9b [2] 98 9d [2] 84 9a [2] 98 b5 }

  condition:
    any of them
}