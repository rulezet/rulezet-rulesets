rule TTP_XOR_MULT_DOSStub_9425 {
  strings:
    $key_9425 = { c0 4d [2] b4 55 [2] f3 57 [2] b4 46 [2] fa 4a [2] f6 40 [2] e1 4b [2] fa 05 [2] c7 }

  condition:
    any of them
}