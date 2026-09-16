rule TTP_XOR_MULT_DOSStub_f5e5 {
  strings:
    $key_f5e5 = { a1 8d [2] d5 95 [2] 92 97 [2] d5 86 [2] 9b 8a [2] 97 80 [2] 80 8b [2] 9b c5 [2] a6 }

  condition:
    any of them
}