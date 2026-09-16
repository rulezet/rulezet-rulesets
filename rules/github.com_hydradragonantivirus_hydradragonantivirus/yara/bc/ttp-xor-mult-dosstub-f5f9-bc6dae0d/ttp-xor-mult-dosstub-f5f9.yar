rule TTP_XOR_MULT_DOSStub_f5f9 {
  strings:
    $key_f5f9 = { a1 91 [2] d5 89 [2] 92 8b [2] d5 9a [2] 9b 96 [2] 97 9c [2] 80 97 [2] 9b d9 [2] a6 }

  condition:
    any of them
}