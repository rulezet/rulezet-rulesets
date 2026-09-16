rule TTP_XOR_MULT_DOSStub_a006 {
  strings:
    $key_a006 = { f4 6e [2] 80 76 [2] c7 74 [2] 80 65 [2] ce 69 [2] c2 63 [2] d5 68 [2] ce 26 [2] f3 }

  condition:
    any of them
}