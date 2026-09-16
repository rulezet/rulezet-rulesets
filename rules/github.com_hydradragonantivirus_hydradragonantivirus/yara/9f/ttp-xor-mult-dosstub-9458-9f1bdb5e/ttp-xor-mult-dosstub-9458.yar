rule TTP_XOR_MULT_DOSStub_9458 {
  strings:
    $key_9458 = { c0 30 [2] b4 28 [2] f3 2a [2] b4 3b [2] fa 37 [2] f6 3d [2] e1 36 [2] fa 78 [2] c7 }

  condition:
    any of them
}