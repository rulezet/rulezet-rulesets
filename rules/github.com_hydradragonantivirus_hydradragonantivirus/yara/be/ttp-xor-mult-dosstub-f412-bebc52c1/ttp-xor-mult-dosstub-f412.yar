rule TTP_XOR_MULT_DOSStub_f412 {
  strings:
    $key_f412 = { a0 7a [2] d4 62 [2] 93 60 [2] d4 71 [2] 9a 7d [2] 96 77 [2] 81 7c [2] 9a 32 [2] a7 }

  condition:
    any of them
}