rule TTP_XOR_MULT_DOSStub_a069 {
  strings:
    $key_a069 = { f4 01 [2] 80 19 [2] c7 1b [2] 80 0a [2] ce 06 [2] c2 0c [2] d5 07 [2] ce 49 [2] f3 }

  condition:
    any of them
}