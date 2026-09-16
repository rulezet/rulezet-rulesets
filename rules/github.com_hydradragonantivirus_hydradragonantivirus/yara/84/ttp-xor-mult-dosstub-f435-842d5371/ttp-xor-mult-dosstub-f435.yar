rule TTP_XOR_MULT_DOSStub_f435 {
  strings:
    $key_f435 = { a0 5d [2] d4 45 [2] 93 47 [2] d4 56 [2] 9a 5a [2] 96 50 [2] 81 5b [2] 9a 15 [2] a7 }

  condition:
    any of them
}