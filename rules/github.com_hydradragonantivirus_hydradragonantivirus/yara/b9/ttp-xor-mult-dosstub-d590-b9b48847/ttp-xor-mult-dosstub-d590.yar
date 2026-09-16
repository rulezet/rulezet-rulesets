rule TTP_XOR_MULT_DOSStub_d590 {
  strings:
    $key_d590 = { 81 f8 [2] f5 e0 [2] b2 e2 [2] f5 f3 [2] bb ff [2] b7 f5 [2] a0 fe [2] bb b0 [2] 86 }

  condition:
    any of them
}