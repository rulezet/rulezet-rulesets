rule TTP_XOR_MULT_DOSStub_9073 {
  strings:
    $key_9073 = { c4 1b [2] b0 03 [2] f7 01 [2] b0 10 [2] fe 1c [2] f2 16 [2] e5 1d [2] fe 53 [2] c3 }

  condition:
    any of them
}