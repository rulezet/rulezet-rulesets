rule TTP_XOR_MULT_DOSStub_f799 {
  strings:
    $key_f799 = { a3 f1 [2] d7 e9 [2] 90 eb [2] d7 fa [2] 99 f6 [2] 95 fc [2] 82 f7 [2] 99 b9 [2] a4 }

  condition:
    any of them
}