rule TTP_XOR_MULT_DOSStub_901b {
  strings:
    $key_901b = { c4 73 [2] b0 6b [2] f7 69 [2] b0 78 [2] fe 74 [2] f2 7e [2] e5 75 [2] fe 3b [2] c3 }

  condition:
    any of them
}