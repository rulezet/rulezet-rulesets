rule TTP_XOR_MULT_DOSStub_9769 {
  strings:
    $key_9769 = { c3 01 [2] b7 19 [2] f0 1b [2] b7 0a [2] f9 06 [2] f5 0c [2] e2 07 [2] f9 49 [2] c4 }

  condition:
    any of them
}