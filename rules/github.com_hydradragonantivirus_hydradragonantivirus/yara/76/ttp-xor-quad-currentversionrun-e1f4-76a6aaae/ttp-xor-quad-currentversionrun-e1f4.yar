rule TTP_XOR_QUAD_CurrentVersionRun_e1f4 {
  strings:
    $key_e1f4 = { b2 9b [2] 96 95 [2] bd b9 [2] 93 9b [2] 87 80 [2] 88 9a [2] 96 87 [2] 94 86 [2] 8f 80 [2] 93 87 [2] 8f a8 }

  condition:
    any of them
}