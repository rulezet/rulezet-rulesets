rule TTP_XOR_MULT_DOSStub_f75b {
  strings:
    $key_f75b = { a3 33 [2] d7 2b [2] 90 29 [2] d7 38 [2] 99 34 [2] 95 3e [2] 82 35 [2] 99 7b [2] a4 }

  condition:
    any of them
}