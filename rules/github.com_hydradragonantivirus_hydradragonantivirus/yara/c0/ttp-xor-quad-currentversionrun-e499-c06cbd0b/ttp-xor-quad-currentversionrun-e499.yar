rule TTP_XOR_QUAD_CurrentVersionRun_e499 {
  strings:
    $key_e499 = { b7 f6 [2] 93 f8 [2] b8 d4 [2] 96 f6 [2] 82 ed [2] 8d f7 [2] 93 ea [2] 91 eb [2] 8a ed [2] 96 ea [2] 8a c5 }

  condition:
    any of them
}