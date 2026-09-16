rule TTP_XOR_MULT_DOSStub_f794 {
  strings:
    $key_f794 = { a3 fc [2] d7 e4 [2] 90 e6 [2] d7 f7 [2] 99 fb [2] 95 f1 [2] 82 fa [2] 99 b4 [2] a4 }

  condition:
    any of them
}