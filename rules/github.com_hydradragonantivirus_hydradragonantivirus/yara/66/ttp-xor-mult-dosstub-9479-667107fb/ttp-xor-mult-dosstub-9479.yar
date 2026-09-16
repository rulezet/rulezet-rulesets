rule TTP_XOR_MULT_DOSStub_9479 {
  strings:
    $key_9479 = { c0 11 [2] b4 09 [2] f3 0b [2] b4 1a [2] fa 16 [2] f6 1c [2] e1 17 [2] fa 59 [2] c7 }

  condition:
    any of them
}