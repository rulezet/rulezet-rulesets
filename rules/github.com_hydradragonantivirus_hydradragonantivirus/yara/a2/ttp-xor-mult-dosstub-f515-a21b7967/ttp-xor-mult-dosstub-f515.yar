rule TTP_XOR_MULT_DOSStub_f515 {
  strings:
    $key_f515 = { a1 7d [2] d5 65 [2] 92 67 [2] d5 76 [2] 9b 7a [2] 97 70 [2] 80 7b [2] 9b 35 [2] a6 }

  condition:
    any of them
}