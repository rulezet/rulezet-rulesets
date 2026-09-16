rule TTP_XOR_MULT_DOSStub_f892 {
  strings:
    $key_f892 = { ac fa [2] d8 e2 [2] 9f e0 [2] d8 f1 [2] 96 fd [2] 9a f7 [2] 8d fc [2] 96 b2 [2] ab }

  condition:
    any of them
}