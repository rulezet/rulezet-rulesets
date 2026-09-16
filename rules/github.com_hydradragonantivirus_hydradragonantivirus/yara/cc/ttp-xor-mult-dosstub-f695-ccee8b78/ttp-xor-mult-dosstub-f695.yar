rule TTP_XOR_MULT_DOSStub_f695 {
  strings:
    $key_f695 = { a2 fd [2] d6 e5 [2] 91 e7 [2] d6 f6 [2] 98 fa [2] 94 f0 [2] 83 fb [2] 98 b5 [2] a5 }

  condition:
    any of them
}