rule TTP_XOR_MULT_DOSStub_f77a {
  strings:
    $key_f77a = { a3 12 [2] d7 0a [2] 90 08 [2] d7 19 [2] 99 15 [2] 95 1f [2] 82 14 [2] 99 5a [2] a4 }

  condition:
    any of them
}