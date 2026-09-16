rule TTP_XOR_MULT_DOSStub_9422 {
  strings:
    $key_9422 = { c0 4a [2] b4 52 [2] f3 50 [2] b4 41 [2] fa 4d [2] f6 47 [2] e1 4c [2] fa 02 [2] c7 }

  condition:
    any of them
}