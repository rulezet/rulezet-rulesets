rule TTP_XOR_MULT_DOSStub_a0eb {
  strings:
    $key_a0eb = { f4 83 [2] 80 9b [2] c7 99 [2] 80 88 [2] ce 84 [2] c2 8e [2] d5 85 [2] ce cb [2] f3 }

  condition:
    any of them
}