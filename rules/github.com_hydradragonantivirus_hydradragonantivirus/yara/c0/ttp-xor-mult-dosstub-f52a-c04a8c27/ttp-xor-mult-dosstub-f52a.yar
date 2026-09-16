rule TTP_XOR_MULT_DOSStub_f52a {
  strings:
    $key_f52a = { a1 42 [2] d5 5a [2] 92 58 [2] d5 49 [2] 9b 45 [2] 97 4f [2] 80 44 [2] 9b 0a [2] a6 }

  condition:
    any of them
}