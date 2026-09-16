rule TTP_XOR_MULT_DOSStub_f514 {
  strings:
    $key_f514 = { a1 7c [2] d5 64 [2] 92 66 [2] d5 77 [2] 9b 7b [2] 97 71 [2] 80 7a [2] 9b 34 [2] a6 }

  condition:
    any of them
}