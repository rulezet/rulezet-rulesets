rule TTP_XOR_MULT_DOSStub_f686 {
  strings:
    $key_f686 = { a2 ee [2] d6 f6 [2] 91 f4 [2] d6 e5 [2] 98 e9 [2] 94 e3 [2] 83 e8 [2] 98 a6 [2] a5 }

  condition:
    any of them
}