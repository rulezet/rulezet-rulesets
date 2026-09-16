rule TTP_XOR_MULT_DOSStub_97ef {
  strings:
    $key_97ef = { c3 87 [2] b7 9f [2] f0 9d [2] b7 8c [2] f9 80 [2] f5 8a [2] e2 81 [2] f9 cf [2] c4 }

  condition:
    any of them
}