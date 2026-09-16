rule TTP_XOR_QUAD_CurrentVersionRun_e68b {
  strings:
    $key_e68b = { b5 e4 [2] 91 ea [2] ba c6 [2] 94 e4 [2] 80 ff [2] 8f e5 [2] 91 f8 [2] 93 f9 [2] 88 ff [2] 94 f8 [2] 88 d7 }

  condition:
    any of them
}