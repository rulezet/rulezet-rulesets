rule TTP_XOR_MULT_DOSStub_f768 {
  strings:
    $key_f768 = { a3 00 [2] d7 18 [2] 90 1a [2] d7 0b [2] 99 07 [2] 95 0d [2] 82 06 [2] 99 48 [2] a4 }

  condition:
    any of them
}