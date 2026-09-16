rule TTP_XOR_MULT_DOSStub_9419 {
  strings:
    $key_9419 = { c0 71 [2] b4 69 [2] f3 6b [2] b4 7a [2] fa 76 [2] f6 7c [2] e1 77 [2] fa 39 [2] c7 }

  condition:
    any of them
}