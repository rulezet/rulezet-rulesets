rule TTP_XOR_MULT_DOSStub_ae92 {
  strings:
    $key_ae92 = { fa fa [2] 8e e2 [2] c9 e0 [2] 8e f1 [2] c0 fd [2] cc f7 [2] db fc [2] c0 b2 [2] fd }

  condition:
    any of them
}