rule TTP_XOR_MULT_DOSStub_9413 {
  strings:
    $key_9413 = { c0 7b [2] b4 63 [2] f3 61 [2] b4 70 [2] fa 7c [2] f6 76 [2] e1 7d [2] fa 33 [2] c7 }

  condition:
    any of them
}