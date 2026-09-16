rule TTP_XOR_MULT_DOSStub_bf82 {
  strings:
    $key_bf82 = { eb ea [2] 9f f2 [2] d8 f0 [2] 9f e1 [2] d1 ed [2] dd e7 [2] ca ec [2] d1 a2 [2] ec }

  condition:
    any of them
}