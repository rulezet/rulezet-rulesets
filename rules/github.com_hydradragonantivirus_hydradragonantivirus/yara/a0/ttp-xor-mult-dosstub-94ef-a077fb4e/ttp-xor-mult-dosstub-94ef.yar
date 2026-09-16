rule TTP_XOR_MULT_DOSStub_94ef {
  strings:
    $key_94ef = { c0 87 [2] b4 9f [2] f3 9d [2] b4 8c [2] fa 80 [2] f6 8a [2] e1 81 [2] fa cf [2] c7 }

  condition:
    any of them
}