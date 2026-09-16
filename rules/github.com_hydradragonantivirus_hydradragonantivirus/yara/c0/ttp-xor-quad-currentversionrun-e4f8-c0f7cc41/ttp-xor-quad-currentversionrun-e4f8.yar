rule TTP_XOR_QUAD_CurrentVersionRun_e4f8 {
  strings:
    $key_e4f8 = { b7 97 [2] 93 99 [2] b8 b5 [2] 96 97 [2] 82 8c [2] 8d 96 [2] 93 8b [2] 91 8a [2] 8a 8c [2] 96 8b [2] 8a a4 }

  condition:
    any of them
}