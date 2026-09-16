rule TTP_XOR_MULT_DOSStub_a0f2 {
  strings:
    $key_a0f2 = { f4 9a [2] 80 82 [2] c7 80 [2] 80 91 [2] ce 9d [2] c2 97 [2] d5 9c [2] ce d2 [2] f3 }

  condition:
    any of them
}