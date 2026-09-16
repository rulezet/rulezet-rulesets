rule TTP_XOR_QUAD_CurrentVersionRun_fae5 {
  strings:
    $key_fae5 = { a9 8a [2] 8d 84 [2] a6 a8 [2] 88 8a [2] 9c 91 [2] 93 8b [2] 8d 96 [2] 8f 97 [2] 94 91 [2] 88 96 [2] 94 b9 }

  condition:
    any of them
}