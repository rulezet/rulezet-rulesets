rule TTP_XOR_MULT_DOSStub_9432 {
  strings:
    $key_9432 = { c0 5a [2] b4 42 [2] f3 40 [2] b4 51 [2] fa 5d [2] f6 57 [2] e1 5c [2] fa 12 [2] c7 }

  condition:
    any of them
}