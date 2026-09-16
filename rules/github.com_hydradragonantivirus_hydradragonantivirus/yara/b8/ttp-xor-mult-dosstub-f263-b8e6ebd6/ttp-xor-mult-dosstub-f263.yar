rule TTP_XOR_MULT_DOSStub_f263 {
  strings:
    $key_f263 = { a6 0b [2] d2 13 [2] 95 11 [2] d2 00 [2] 9c 0c [2] 90 06 [2] 87 0d [2] 9c 43 [2] a1 }

  condition:
    any of them
}