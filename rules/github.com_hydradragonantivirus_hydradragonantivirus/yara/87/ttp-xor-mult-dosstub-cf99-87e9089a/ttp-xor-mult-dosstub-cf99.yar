rule TTP_XOR_MULT_DOSStub_cf99 {
  strings:
    $key_cf99 = { 9b f1 [2] ef e9 [2] a8 eb [2] ef fa [2] a1 f6 [2] ad fc [2] ba f7 [2] a1 b9 [2] 9c }

  condition:
    any of them
}