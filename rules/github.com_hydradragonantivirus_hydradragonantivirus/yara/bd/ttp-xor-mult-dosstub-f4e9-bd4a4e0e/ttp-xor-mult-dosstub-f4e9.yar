rule TTP_XOR_MULT_DOSStub_f4e9 {
  strings:
    $key_f4e9 = { a0 81 [2] d4 99 [2] 93 9b [2] d4 8a [2] 9a 86 [2] 96 8c [2] 81 87 [2] 9a c9 [2] a7 }

  condition:
    any of them
}