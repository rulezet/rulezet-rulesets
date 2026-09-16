rule TTP_XOR_MULT_DOSStub_a0f5 {
  strings:
    $key_a0f5 = { f4 9d [2] 80 85 [2] c7 87 [2] 80 96 [2] ce 9a [2] c2 90 [2] d5 9b [2] ce d5 [2] f3 }

  condition:
    any of them
}