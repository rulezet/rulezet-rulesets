rule TTP_XOR_MULT_DOSStub_f099 {
  strings:
    $key_f099 = { a4 f1 [2] d0 e9 [2] 97 eb [2] d0 fa [2] 9e f6 [2] 92 fc [2] 85 f7 [2] 9e b9 [2] a3 }

  condition:
    any of them
}