rule TTP_XOR_MULT_DOSStub_f5f8 {
  strings:
    $key_f5f8 = { a1 90 [2] d5 88 [2] 92 8a [2] d5 9b [2] 9b 97 [2] 97 9d [2] 80 96 [2] 9b d8 [2] a6 }

  condition:
    any of them
}