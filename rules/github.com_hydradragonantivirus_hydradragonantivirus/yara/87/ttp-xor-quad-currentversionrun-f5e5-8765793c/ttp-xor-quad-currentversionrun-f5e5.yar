rule TTP_XOR_QUAD_CurrentVersionRun_f5e5 {
  strings:
    $key_f5e5 = { a6 8a [2] 82 84 [2] a9 a8 [2] 87 8a [2] 93 91 [2] 9c 8b [2] 82 96 [2] 80 97 [2] 9b 91 [2] 87 96 [2] 9b b9 }

  condition:
    any of them
}