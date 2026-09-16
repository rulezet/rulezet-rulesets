rule TTP_XOR_MULT_DOSStub_85ef {
  strings:
    $key_85ef = { d1 87 [2] a5 9f [2] e2 9d [2] a5 8c [2] eb 80 [2] e7 8a [2] f0 81 [2] eb cf [2] d6 }

  condition:
    any of them
}