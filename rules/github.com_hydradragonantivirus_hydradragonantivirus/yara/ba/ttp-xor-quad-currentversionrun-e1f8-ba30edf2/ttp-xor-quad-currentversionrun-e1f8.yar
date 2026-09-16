rule TTP_XOR_QUAD_CurrentVersionRun_e1f8 {
  strings:
    $key_e1f8 = { b2 97 [2] 96 99 [2] bd b5 [2] 93 97 [2] 87 8c [2] 88 96 [2] 96 8b [2] 94 8a [2] 8f 8c [2] 93 8b [2] 8f a4 }

  condition:
    any of them
}