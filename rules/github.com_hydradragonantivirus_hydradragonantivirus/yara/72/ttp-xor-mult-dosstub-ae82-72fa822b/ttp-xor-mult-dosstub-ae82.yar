rule TTP_XOR_MULT_DOSStub_ae82 {
  strings:
    $key_ae82 = { fa ea [2] 8e f2 [2] c9 f0 [2] 8e e1 [2] c0 ed [2] cc e7 [2] db ec [2] c0 a2 [2] fd }

  condition:
    any of them
}