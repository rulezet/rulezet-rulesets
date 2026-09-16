rule TTP_XOR_MULT_DOSStub_9748 {
  strings:
    $key_9748 = { c3 20 [2] b7 38 [2] f0 3a [2] b7 2b [2] f9 27 [2] f5 2d [2] e2 26 [2] f9 68 [2] c4 }

  condition:
    any of them
}