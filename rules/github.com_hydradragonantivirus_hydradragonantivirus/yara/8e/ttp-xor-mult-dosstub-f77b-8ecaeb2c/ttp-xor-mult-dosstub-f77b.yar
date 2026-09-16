rule TTP_XOR_MULT_DOSStub_f77b {
  strings:
    $key_f77b = { a3 13 [2] d7 0b [2] 90 09 [2] d7 18 [2] 99 14 [2] 95 1e [2] 82 15 [2] 99 5b [2] a4 }

  condition:
    any of them
}