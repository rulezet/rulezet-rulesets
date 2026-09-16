rule TTP_XOR_MULT_DOSStub_bf8a {
  strings:
    $key_bf8a = { eb e2 [2] 9f fa [2] d8 f8 [2] 9f e9 [2] d1 e5 [2] dd ef [2] ca e4 [2] d1 aa [2] ec }

  condition:
    any of them
}