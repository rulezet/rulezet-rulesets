rule TTP_XOR_MULT_DOSStub_f205 {
  strings:
    $key_f205 = { a6 6d [2] d2 75 [2] 95 77 [2] d2 66 [2] 9c 6a [2] 90 60 [2] 87 6b [2] 9c 25 [2] a1 }

  condition:
    any of them
}