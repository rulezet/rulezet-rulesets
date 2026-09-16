rule TTP_XOR_MULT_DOSStub_bf92 {
  strings:
    $key_bf92 = { eb fa [2] 9f e2 [2] d8 e0 [2] 9f f1 [2] d1 fd [2] dd f7 [2] ca fc [2] d1 b2 [2] ec }

  condition:
    any of them
}