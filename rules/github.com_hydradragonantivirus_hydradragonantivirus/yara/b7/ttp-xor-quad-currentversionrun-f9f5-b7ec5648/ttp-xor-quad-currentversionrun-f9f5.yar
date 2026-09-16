rule TTP_XOR_QUAD_CurrentVersionRun_f9f5 {
  strings:
    $key_f9f5 = { aa 9a [2] 8e 94 [2] a5 b8 [2] 8b 9a [2] 9f 81 [2] 90 9b [2] 8e 86 [2] 8c 87 [2] 97 81 [2] 8b 86 [2] 97 a9 }

  condition:
    any of them
}