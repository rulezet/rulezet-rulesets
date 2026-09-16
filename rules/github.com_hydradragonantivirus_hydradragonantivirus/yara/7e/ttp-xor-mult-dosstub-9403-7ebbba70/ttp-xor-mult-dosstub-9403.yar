rule TTP_XOR_MULT_DOSStub_9403 {
  strings:
    $key_9403 = { c0 6b [2] b4 73 [2] f3 71 [2] b4 60 [2] fa 6c [2] f6 66 [2] e1 6d [2] fa 23 [2] c7 }

  condition:
    any of them
}