rule TTP_XOR_MULT_DOSStub_bc99 {
  strings:
    $key_bc99 = { e8 f1 [2] 9c e9 [2] db eb [2] 9c fa [2] d2 f6 [2] de fc [2] c9 f7 [2] d2 b9 [2] ef }

  condition:
    any of them
}