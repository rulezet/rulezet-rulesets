rule TTP_XOR_MULT_DOSStub_9429 {
  strings:
    $key_9429 = { c0 41 [2] b4 59 [2] f3 5b [2] b4 4a [2] fa 46 [2] f6 4c [2] e1 47 [2] fa 09 [2] c7 }

  condition:
    any of them
}