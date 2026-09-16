rule TTP_XOR_MULT_DOSStub_f181 {
  strings:
    $key_f181 = { a5 e9 [2] d1 f1 [2] 96 f3 [2] d1 e2 [2] 9f ee [2] 93 e4 [2] 84 ef [2] 9f a1 [2] a2 }

  condition:
    any of them
}