rule TTP_XOR_MULT_DOSStub_a023 {
  strings:
    $key_a023 = { f4 4b [2] 80 53 [2] c7 51 [2] 80 40 [2] ce 4c [2] c2 46 [2] d5 4d [2] ce 03 [2] f3 }

  condition:
    any of them
}