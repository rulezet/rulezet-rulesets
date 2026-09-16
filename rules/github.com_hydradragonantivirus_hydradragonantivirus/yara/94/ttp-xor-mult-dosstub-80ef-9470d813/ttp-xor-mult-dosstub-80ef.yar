rule TTP_XOR_MULT_DOSStub_80ef {
  strings:
    $key_80ef = { d4 87 [2] a0 9f [2] e7 9d [2] a0 8c [2] ee 80 [2] e2 8a [2] f5 81 [2] ee cf [2] d3 }

  condition:
    any of them
}