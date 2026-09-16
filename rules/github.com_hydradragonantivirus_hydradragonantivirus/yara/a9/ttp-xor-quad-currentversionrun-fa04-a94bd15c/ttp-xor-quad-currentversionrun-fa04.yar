rule TTP_XOR_QUAD_CurrentVersionRun_fa04 {
  strings:
    $key_fa04 = { a9 6b [2] 8d 65 [2] a6 49 [2] 88 6b [2] 9c 70 [2] 93 6a [2] 8d 77 [2] 8f 76 [2] 94 70 [2] 88 77 [2] 94 58 }

  condition:
    any of them
}