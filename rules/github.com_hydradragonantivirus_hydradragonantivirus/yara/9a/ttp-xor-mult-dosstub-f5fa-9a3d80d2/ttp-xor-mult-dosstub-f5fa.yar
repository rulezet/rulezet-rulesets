rule TTP_XOR_MULT_DOSStub_f5fa {
  strings:
    $key_f5fa = { a1 92 [2] d5 8a [2] 92 88 [2] d5 99 [2] 9b 95 [2] 97 9f [2] 80 94 [2] 9b da [2] a6 }

  condition:
    any of them
}