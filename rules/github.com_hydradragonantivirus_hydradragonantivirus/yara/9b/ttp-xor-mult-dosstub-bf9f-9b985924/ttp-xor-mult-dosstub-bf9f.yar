rule TTP_XOR_MULT_DOSStub_bf9f {
  strings:
    $key_bf9f = { eb f7 [2] 9f ef [2] d8 ed [2] 9f fc [2] d1 f0 [2] dd fa [2] ca f1 [2] d1 bf [2] ec }

  condition:
    any of them
}