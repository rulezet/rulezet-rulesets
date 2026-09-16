rule TTP_XOR_MULT_DOSStub_f535 {
  strings:
    $key_f535 = { a1 5d [2] d5 45 [2] 92 47 [2] d5 56 [2] 9b 5a [2] 97 50 [2] 80 5b [2] 9b 15 [2] a6 }

  condition:
    any of them
}