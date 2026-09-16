rule TTP_XOR_MULT_DOSStub_f504 {
  strings:
    $key_f504 = { a1 6c [2] d5 74 [2] 92 76 [2] d5 67 [2] 9b 6b [2] 97 61 [2] 80 6a [2] 9b 24 [2] a6 }

  condition:
    any of them
}