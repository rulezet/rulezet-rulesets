rule TTP_XOR_MULT_DOSStub_9453 {
  strings:
    $key_9453 = { c0 3b [2] b4 23 [2] f3 21 [2] b4 30 [2] fa 3c [2] f6 36 [2] e1 3d [2] fa 73 [2] c7 }

  condition:
    any of them
}