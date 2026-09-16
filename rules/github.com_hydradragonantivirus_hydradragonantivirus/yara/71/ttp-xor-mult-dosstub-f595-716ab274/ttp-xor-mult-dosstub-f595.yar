rule TTP_XOR_MULT_DOSStub_f595 {
  strings:
    $key_f595 = { a1 fd [2] d5 e5 [2] 92 e7 [2] d5 f6 [2] 9b fa [2] 97 f0 [2] 80 fb [2] 9b b5 [2] a6 }

  condition:
    any of them
}