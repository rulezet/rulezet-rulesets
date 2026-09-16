rule TTP_XOR_MULT_DOSStub_ac99 {
  strings:
    $key_ac99 = { f8 f1 [2] 8c e9 [2] cb eb [2] 8c fa [2] c2 f6 [2] ce fc [2] d9 f7 [2] c2 b9 [2] ff }

  condition:
    any of them
}