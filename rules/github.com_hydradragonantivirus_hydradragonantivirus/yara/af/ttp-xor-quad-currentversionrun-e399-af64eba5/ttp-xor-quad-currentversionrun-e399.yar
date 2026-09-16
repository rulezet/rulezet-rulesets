rule TTP_XOR_QUAD_CurrentVersionRun_e399 {
  strings:
    $key_e399 = { b0 f6 [2] 94 f8 [2] bf d4 [2] 91 f6 [2] 85 ed [2] 8a f7 [2] 94 ea [2] 96 eb [2] 8d ed [2] 91 ea [2] 8d c5 }

  condition:
    any of them
}