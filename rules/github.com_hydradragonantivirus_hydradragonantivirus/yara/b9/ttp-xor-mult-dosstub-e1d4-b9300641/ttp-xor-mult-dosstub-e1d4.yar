rule TTP_XOR_MULT_DOSStub_e1d4 {
  strings:
    $key_e1d4 = { b5 bc [2] c1 a4 [2] 86 a6 [2] c1 b7 [2] 8f bb [2] 83 b1 [2] 94 ba [2] 8f f4 [2] b2 }

  condition:
    any of them
}