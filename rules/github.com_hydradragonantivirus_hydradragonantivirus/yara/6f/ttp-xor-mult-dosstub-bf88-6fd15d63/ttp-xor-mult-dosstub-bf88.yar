rule TTP_XOR_MULT_DOSStub_bf88 {
  strings:
    $key_bf88 = { eb e0 [2] 9f f8 [2] d8 fa [2] 9f eb [2] d1 e7 [2] dd ed [2] ca e6 [2] d1 a8 [2] ec }

  condition:
    any of them
}