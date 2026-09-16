rule TTP_XOR_MULT_DOSStub_bf80 {
  strings:
    $key_bf80 = { eb e8 [2] 9f f0 [2] d8 f2 [2] 9f e3 [2] d1 ef [2] dd e5 [2] ca ee [2] d1 a0 [2] ec }

  condition:
    any of them
}