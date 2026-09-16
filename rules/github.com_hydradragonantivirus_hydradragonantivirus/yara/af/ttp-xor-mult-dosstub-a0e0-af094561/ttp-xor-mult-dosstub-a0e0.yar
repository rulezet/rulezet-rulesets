rule TTP_XOR_MULT_DOSStub_a0e0 {
  strings:
    $key_a0e0 = { f4 88 [2] 80 90 [2] c7 92 [2] 80 83 [2] ce 8f [2] c2 85 [2] d5 8e [2] ce c0 [2] f3 }

  condition:
    any of them
}