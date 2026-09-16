rule TTP_XOR_MULT_DOSStub_f299 {
  strings:
    $key_f299 = { a6 f1 [2] d2 e9 [2] 95 eb [2] d2 fa [2] 9c f6 [2] 90 fc [2] 87 f7 [2] 9c b9 [2] a1 }

  condition:
    any of them
}