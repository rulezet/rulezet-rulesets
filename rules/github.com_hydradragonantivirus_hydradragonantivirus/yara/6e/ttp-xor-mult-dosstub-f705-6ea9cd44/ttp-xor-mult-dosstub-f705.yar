rule TTP_XOR_MULT_DOSStub_f705 {
  strings:
    $key_f705 = { a3 6d [2] d7 75 [2] 90 77 [2] d7 66 [2] 99 6a [2] 95 60 [2] 82 6b [2] 99 25 [2] a4 }

  condition:
    any of them
}