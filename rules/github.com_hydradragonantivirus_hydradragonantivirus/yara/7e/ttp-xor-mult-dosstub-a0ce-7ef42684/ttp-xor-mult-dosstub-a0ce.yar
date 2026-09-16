rule TTP_XOR_MULT_DOSStub_a0ce {
  strings:
    $key_a0ce = { f4 a6 [2] 80 be [2] c7 bc [2] 80 ad [2] ce a1 [2] c2 ab [2] d5 a0 [2] ce ee [2] f3 }

  condition:
    any of them
}