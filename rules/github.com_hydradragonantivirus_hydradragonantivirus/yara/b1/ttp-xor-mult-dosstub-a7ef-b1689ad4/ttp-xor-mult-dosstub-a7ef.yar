rule TTP_XOR_MULT_DOSStub_a7ef {
  strings:
    $key_a7ef = { f3 87 [2] 87 9f [2] c0 9d [2] 87 8c [2] c9 80 [2] c5 8a [2] d2 81 [2] c9 cf [2] f4 }

  condition:
    any of them
}