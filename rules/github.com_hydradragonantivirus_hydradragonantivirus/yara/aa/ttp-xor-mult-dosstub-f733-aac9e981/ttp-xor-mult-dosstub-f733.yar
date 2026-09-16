rule TTP_XOR_MULT_DOSStub_f733 {
  strings:
    $key_f733 = { a3 5b [2] d7 43 [2] 90 41 [2] d7 50 [2] 99 5c [2] 95 56 [2] 82 5d [2] 99 13 [2] a4 }

  condition:
    any of them
}