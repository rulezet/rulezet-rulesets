rule TTP_XOR_MULT_DOSStub_f6d6 {
  strings:
    $key_f6d6 = { a2 be [2] d6 a6 [2] 91 a4 [2] d6 b5 [2] 98 b9 [2] 94 b3 [2] 83 b8 [2] 98 f6 [2] a5 }

  condition:
    any of them
}