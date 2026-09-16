rule TTP_XOR_MULT_DOSStub_a031 {
  strings:
    $key_a031 = { f4 59 [2] 80 41 [2] c7 43 [2] 80 52 [2] ce 5e [2] c2 54 [2] d5 5f [2] ce 11 [2] f3 }

  condition:
    any of them
}