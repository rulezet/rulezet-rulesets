rule TTP_XOR_MULT_DOSStub_a061 {
  strings:
    $key_a061 = { f4 09 [2] 80 11 [2] c7 13 [2] 80 02 [2] ce 0e [2] c2 04 [2] d5 0f [2] ce 41 [2] f3 }

  condition:
    any of them
}