rule TTP_XOR_QUAD_CurrentVersionRun_fae8 {
  strings:
    $key_fae8 = { a9 87 [2] 8d 89 [2] a6 a5 [2] 88 87 [2] 9c 9c [2] 93 86 [2] 8d 9b [2] 8f 9a [2] 94 9c [2] 88 9b [2] 94 b4 }

  condition:
    any of them
}