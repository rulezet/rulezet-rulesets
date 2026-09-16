rule TTP_XOR_MULT_DOSStub_f414 {
  strings:
    $key_f414 = { a0 7c [2] d4 64 [2] 93 66 [2] d4 77 [2] 9a 7b [2] 96 71 [2] 81 7a [2] 9a 34 [2] a7 }

  condition:
    any of them
}