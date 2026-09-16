rule TTP_XOR_QUAD_CurrentVersionRun_e684 {
  strings:
    $key_e684 = { b5 eb [2] 91 e5 [2] ba c9 [2] 94 eb [2] 80 f0 [2] 8f ea [2] 91 f7 [2] 93 f6 [2] 88 f0 [2] 94 f7 [2] 88 d8 }

  condition:
    any of them
}