rule TTP_XOR_MULT_DOSStub_9418 {
  strings:
    $key_9418 = { c0 70 [2] b4 68 [2] f3 6a [2] b4 7b [2] fa 77 [2] f6 7d [2] e1 76 [2] fa 38 [2] c7 }

  condition:
    any of them
}