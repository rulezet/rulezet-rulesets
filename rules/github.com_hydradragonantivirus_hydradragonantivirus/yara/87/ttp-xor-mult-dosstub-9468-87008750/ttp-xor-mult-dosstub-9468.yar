rule TTP_XOR_MULT_DOSStub_9468 {
  strings:
    $key_9468 = { c0 00 [2] b4 18 [2] f3 1a [2] b4 0b [2] fa 07 [2] f6 0d [2] e1 06 [2] fa 48 [2] c7 }

  condition:
    any of them
}