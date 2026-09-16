rule TTP_XOR_MULT_DOSStub_bf83 {
  strings:
    $key_bf83 = { eb eb [2] 9f f3 [2] d8 f1 [2] 9f e0 [2] d1 ec [2] dd e6 [2] ca ed [2] d1 a3 [2] ec }

  condition:
    any of them
}