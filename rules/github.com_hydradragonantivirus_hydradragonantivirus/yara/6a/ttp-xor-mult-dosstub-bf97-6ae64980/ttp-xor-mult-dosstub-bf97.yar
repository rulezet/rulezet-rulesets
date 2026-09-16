rule TTP_XOR_MULT_DOSStub_bf97 {
  strings:
    $key_bf97 = { eb ff [2] 9f e7 [2] d8 e5 [2] 9f f4 [2] d1 f8 [2] dd f2 [2] ca f9 [2] d1 b7 [2] ec }

  condition:
    any of them
}