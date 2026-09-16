rule TTP_XOR_QUAD_CurrentVersionRun_e6c6 {
  strings:
    $key_e6c6 = { b5 a9 [2] 91 a7 [2] ba 8b [2] 94 a9 [2] 80 b2 [2] 8f a8 [2] 91 b5 [2] 93 b4 [2] 88 b2 [2] 94 b5 [2] 88 9a }

  condition:
    any of them
}