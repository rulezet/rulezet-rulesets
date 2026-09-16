rule TTP_XOR_MULT_DOSStub_f518 {
  strings:
    $key_f518 = { a1 70 [2] d5 68 [2] 92 6a [2] d5 7b [2] 9b 77 [2] 97 7d [2] 80 76 [2] 9b 38 [2] a6 }

  condition:
    any of them
}