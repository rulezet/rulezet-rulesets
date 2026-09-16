rule TTP_XOR_MULT_DOSStub_f681 {
  strings:
    $key_f681 = { a2 e9 [2] d6 f1 [2] 91 f3 [2] d6 e2 [2] 98 ee [2] 94 e4 [2] 83 ef [2] 98 a1 [2] a5 }

  condition:
    any of them
}