rule TTP_XOR_MULT_DOSStub_96ef {
  strings:
    $key_96ef = { c2 87 [2] b6 9f [2] f1 9d [2] b6 8c [2] f8 80 [2] f4 8a [2] e3 81 [2] f8 cf [2] c5 }

  condition:
    any of them
}