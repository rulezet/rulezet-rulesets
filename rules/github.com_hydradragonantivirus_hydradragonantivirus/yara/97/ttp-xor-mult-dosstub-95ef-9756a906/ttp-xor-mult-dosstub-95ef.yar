rule TTP_XOR_MULT_DOSStub_95ef {
  strings:
    $key_95ef = { c1 87 [2] b5 9f [2] f2 9d [2] b5 8c [2] fb 80 [2] f7 8a [2] e0 81 [2] fb cf [2] c6 }

  condition:
    any of them
}