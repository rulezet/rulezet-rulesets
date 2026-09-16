rule TTP_XOR_MULT_DOSStub_bf96 {
  strings:
    $key_bf96 = { eb fe [2] 9f e6 [2] d8 e4 [2] 9f f5 [2] d1 f9 [2] dd f3 [2] ca f8 [2] d1 b6 [2] ec }

  condition:
    any of them
}