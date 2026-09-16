rule TTP_XOR_MULT_DOSStub_f465 {
  strings:
    $key_f465 = { a0 0d [2] d4 15 [2] 93 17 [2] d4 06 [2] 9a 0a [2] 96 00 [2] 81 0b [2] 9a 45 [2] a7 }

  condition:
    any of them
}