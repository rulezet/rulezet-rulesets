rule TTP_XOR_QUAD_CurrentVersionRun_f565 {
  strings:
    $key_f565 = { a6 0a [2] 82 04 [2] a9 28 [2] 87 0a [2] 93 11 [2] 9c 0b [2] 82 16 [2] 80 17 [2] 9b 11 [2] 87 16 [2] 9b 39 }

  condition:
    any of them
}