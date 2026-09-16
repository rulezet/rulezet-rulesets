rule TTP_XOR_MULT_DOSStub_a036 {
  strings:
    $key_a036 = { f4 5e [2] 80 46 [2] c7 44 [2] 80 55 [2] ce 59 [2] c2 53 [2] d5 58 [2] ce 16 [2] f3 }

  condition:
    any of them
}