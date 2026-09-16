rule TTP_XOR_MULT_DOSStub_9414 {
  strings:
    $key_9414 = { c0 7c [2] b4 64 [2] f3 66 [2] b4 77 [2] fa 7b [2] f6 71 [2] e1 7a [2] fa 34 [2] c7 }

  condition:
    any of them
}