rule TTP_XOR_MULT_DOSStub_f77c {
  strings:
    $key_f77c = { a3 14 [2] d7 0c [2] 90 0e [2] d7 1f [2] 99 13 [2] 95 19 [2] 82 12 [2] 99 5c [2] a4 }

  condition:
    any of them
}