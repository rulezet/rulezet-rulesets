rule TTP_XOR_MULT_DOSStub_f4f5 {
  strings:
    $key_f4f5 = { a0 9d [2] d4 85 [2] 93 87 [2] d4 96 [2] 9a 9a [2] 96 90 [2] 81 9b [2] 9a d5 [2] a7 }

  condition:
    any of them
}