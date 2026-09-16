rule TTP_XOR_MULT_DOSStub_9507 {
  strings:
    $key_9507 = { c1 6f [2] b5 77 [2] f2 75 [2] b5 64 [2] fb 68 [2] f7 62 [2] e0 69 [2] fb 27 [2] c6 }

  condition:
    any of them
}