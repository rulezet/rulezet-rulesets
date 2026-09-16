rule TTP_XOR_MULT_DOSStub_f777 {
  strings:
    $key_f777 = { a3 1f [2] d7 07 [2] 90 05 [2] d7 14 [2] 99 18 [2] 95 12 [2] 82 19 [2] 99 57 [2] a4 }

  condition:
    any of them
}