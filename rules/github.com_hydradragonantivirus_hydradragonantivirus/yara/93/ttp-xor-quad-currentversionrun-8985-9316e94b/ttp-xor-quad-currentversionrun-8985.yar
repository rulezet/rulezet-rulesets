rule TTP_XOR_QUAD_CurrentVersionRun_8985 {
  strings:
    $key_8985 = { da ea [2] fe e4 [2] d5 c8 [2] fb ea [2] ef f1 [2] e0 eb [2] fe f6 [2] fc f7 [2] e7 f1 [2] fb f6 [2] e7 d9 }

  condition:
    any of them
}