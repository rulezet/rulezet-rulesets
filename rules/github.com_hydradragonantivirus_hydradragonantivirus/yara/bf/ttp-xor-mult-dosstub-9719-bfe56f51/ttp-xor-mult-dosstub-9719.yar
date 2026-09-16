rule TTP_XOR_MULT_DOSStub_9719 {
  strings:
    $key_9719 = { c3 71 [2] b7 69 [2] f0 6b [2] b7 7a [2] f9 76 [2] f5 7c [2] e2 77 [2] f9 39 [2] c4 }

  condition:
    any of them
}