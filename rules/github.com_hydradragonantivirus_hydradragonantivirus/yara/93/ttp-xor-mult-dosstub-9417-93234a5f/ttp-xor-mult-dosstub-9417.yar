rule TTP_XOR_MULT_DOSStub_9417 {
  strings:
    $key_9417 = { c0 7f [2] b4 67 [2] f3 65 [2] b4 74 [2] fa 78 [2] f6 72 [2] e1 79 [2] fa 37 [2] c7 }

  condition:
    any of them
}