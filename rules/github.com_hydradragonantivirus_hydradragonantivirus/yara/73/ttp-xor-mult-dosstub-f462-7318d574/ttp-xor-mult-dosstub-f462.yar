rule TTP_XOR_MULT_DOSStub_f462 {
  strings:
    $key_f462 = { a0 0a [2] d4 12 [2] 93 10 [2] d4 01 [2] 9a 0d [2] 96 07 [2] 81 0c [2] 9a 42 [2] a7 }

  condition:
    any of them
}