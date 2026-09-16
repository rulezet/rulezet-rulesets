rule TTP_XOR_MULT_DOSStub_f680 {
  strings:
    $key_f680 = { a2 e8 [2] d6 f0 [2] 91 f2 [2] d6 e3 [2] 98 ef [2] 94 e5 [2] 83 ee [2] 98 a0 [2] a5 }

  condition:
    any of them
}