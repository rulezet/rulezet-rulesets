rule TTP_XOR_MULT_DOSStub_f718 {
  strings:
    $key_f718 = { a3 70 [2] d7 68 [2] 90 6a [2] d7 7b [2] 99 77 [2] 95 7d [2] 82 76 [2] 99 38 [2] a4 }

  condition:
    any of them
}