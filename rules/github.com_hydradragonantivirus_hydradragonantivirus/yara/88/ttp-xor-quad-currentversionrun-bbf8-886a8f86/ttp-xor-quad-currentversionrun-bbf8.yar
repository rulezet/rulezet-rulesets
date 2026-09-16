rule TTP_XOR_QUAD_CurrentVersionRun_bbf8 {
  strings:
    $key_bbf8 = { e8 97 [2] cc 99 [2] e7 b5 [2] c9 97 [2] dd 8c [2] d2 96 [2] cc 8b [2] ce 8a [2] d5 8c [2] c9 8b [2] d5 a4 }

  condition:
    any of them
}