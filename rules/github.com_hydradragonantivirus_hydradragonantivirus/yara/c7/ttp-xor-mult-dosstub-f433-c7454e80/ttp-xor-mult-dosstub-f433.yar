rule TTP_XOR_MULT_DOSStub_f433 {
  strings:
    $key_f433 = { a0 5b [2] d4 43 [2] 93 41 [2] d4 50 [2] 9a 5c [2] 96 56 [2] 81 5d [2] 9a 13 [2] a7 }

  condition:
    any of them
}