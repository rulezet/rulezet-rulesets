rule TTP_XOR_MULT_DOSStub_bf94 {
  strings:
    $key_bf94 = { eb fc [2] 9f e4 [2] d8 e6 [2] 9f f7 [2] d1 fb [2] dd f1 [2] ca fa [2] d1 b4 [2] ec }

  condition:
    any of them
}