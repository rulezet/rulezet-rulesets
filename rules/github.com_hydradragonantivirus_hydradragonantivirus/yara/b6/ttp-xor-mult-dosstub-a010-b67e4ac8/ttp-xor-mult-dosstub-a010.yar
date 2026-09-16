rule TTP_XOR_MULT_DOSStub_a010 {
  strings:
    $key_a010 = { f4 78 [2] 80 60 [2] c7 62 [2] 80 73 [2] ce 7f [2] c2 75 [2] d5 7e [2] ce 30 [2] f3 }

  condition:
    any of them
}