rule TTP_XOR_MULT_DOSStub_f709 {
  strings:
    $key_f709 = { a3 61 [2] d7 79 [2] 90 7b [2] d7 6a [2] 99 66 [2] 95 6c [2] 82 67 [2] 99 29 [2] a4 }

  condition:
    any of them
}