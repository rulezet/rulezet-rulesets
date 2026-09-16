rule TTP_XOR_MULT_DOSStub_f770 {
  strings:
    $key_f770 = { a3 18 [2] d7 00 [2] 90 02 [2] d7 13 [2] 99 1f [2] 95 15 [2] 82 1e [2] 99 50 [2] a4 }

  condition:
    any of them
}