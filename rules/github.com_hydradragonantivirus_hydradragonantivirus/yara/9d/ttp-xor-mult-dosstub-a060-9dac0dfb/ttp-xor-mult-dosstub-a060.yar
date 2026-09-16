rule TTP_XOR_MULT_DOSStub_a060 {
  strings:
    $key_a060 = { f4 08 [2] 80 10 [2] c7 12 [2] 80 03 [2] ce 0f [2] c2 05 [2] d5 0e [2] ce 40 [2] f3 }

  condition:
    any of them
}