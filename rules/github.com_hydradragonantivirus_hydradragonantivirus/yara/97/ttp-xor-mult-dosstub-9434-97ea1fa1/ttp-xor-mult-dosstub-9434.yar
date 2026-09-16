rule TTP_XOR_MULT_DOSStub_9434 {
  strings:
    $key_9434 = { c0 5c [2] b4 44 [2] f3 46 [2] b4 57 [2] fa 5b [2] f6 51 [2] e1 5a [2] fa 14 [2] c7 }

  condition:
    any of them
}