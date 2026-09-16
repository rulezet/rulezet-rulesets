rule TTP_XOR_MULT_DOSStub_f725 {
  strings:
    $key_f725 = { a3 4d [2] d7 55 [2] 90 57 [2] d7 46 [2] 99 4a [2] 95 40 [2] 82 4b [2] 99 05 [2] a4 }

  condition:
    any of them
}