rule TTP_XOR_MULT_DOSStub_9724 {
  strings:
    $key_9724 = { c3 4c [2] b7 54 [2] f0 56 [2] b7 47 [2] f9 4b [2] f5 41 [2] e2 4a [2] f9 04 [2] c4 }

  condition:
    any of them
}