rule TTP_XOR_MULT_DOSStub_a0e3 {
  strings:
    $key_a0e3 = { f4 8b [2] 80 93 [2] c7 91 [2] 80 80 [2] ce 8c [2] c2 86 [2] d5 8d [2] ce c3 [2] f3 }

  condition:
    any of them
}