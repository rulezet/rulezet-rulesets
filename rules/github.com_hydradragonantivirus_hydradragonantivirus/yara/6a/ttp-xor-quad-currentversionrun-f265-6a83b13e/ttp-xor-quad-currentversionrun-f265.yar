rule TTP_XOR_QUAD_CurrentVersionRun_f265 {
  strings:
    $key_f265 = { a1 0a [2] 85 04 [2] ae 28 [2] 80 0a [2] 94 11 [2] 9b 0b [2] 85 16 [2] 87 17 [2] 9c 11 [2] 80 16 [2] 9c 39 }

  condition:
    any of them
}