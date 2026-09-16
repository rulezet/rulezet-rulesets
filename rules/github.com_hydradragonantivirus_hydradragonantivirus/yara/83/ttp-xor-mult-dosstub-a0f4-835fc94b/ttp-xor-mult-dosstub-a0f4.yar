rule TTP_XOR_MULT_DOSStub_a0f4 {
  strings:
    $key_a0f4 = { f4 9c [2] 80 84 [2] c7 86 [2] 80 97 [2] ce 9b [2] c2 91 [2] d5 9a [2] ce d4 [2] f3 }

  condition:
    any of them
}