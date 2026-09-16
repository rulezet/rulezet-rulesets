rule TTP_XOR_QUAD_CurrentVersionRun_fae4 {
  strings:
    $key_fae4 = { a9 8b [2] 8d 85 [2] a6 a9 [2] 88 8b [2] 9c 90 [2] 93 8a [2] 8d 97 [2] 8f 96 [2] 94 90 [2] 88 97 [2] 94 b8 }

  condition:
    any of them
}