rule TTP_XOR_MULT_DOSStub_f133 {
  strings:
    $key_f133 = { a5 5b [2] d1 43 [2] 96 41 [2] d1 50 [2] 9f 5c [2] 93 56 [2] 84 5d [2] 9f 13 [2] a2 }

  condition:
    any of them
}