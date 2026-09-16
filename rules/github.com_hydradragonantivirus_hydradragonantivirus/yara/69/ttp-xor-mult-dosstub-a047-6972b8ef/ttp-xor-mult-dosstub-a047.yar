rule TTP_XOR_MULT_DOSStub_a047 {
  strings:
    $key_a047 = { f4 2f [2] 80 37 [2] c7 35 [2] 80 24 [2] ce 28 [2] c2 22 [2] d5 29 [2] ce 67 [2] f3 }

  condition:
    any of them
}