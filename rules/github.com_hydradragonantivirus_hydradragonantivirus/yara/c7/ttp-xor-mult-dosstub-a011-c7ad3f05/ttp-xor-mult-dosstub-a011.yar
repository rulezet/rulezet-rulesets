rule TTP_XOR_MULT_DOSStub_a011 {
  strings:
    $key_a011 = { f4 79 [2] 80 61 [2] c7 63 [2] 80 72 [2] ce 7e [2] c2 74 [2] d5 7f [2] ce 31 [2] f3 }

  condition:
    any of them
}