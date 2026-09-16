rule TTP_XOR_MULT_DOSStub_961b {
  strings:
    $key_961b = { c2 73 [2] b6 6b [2] f1 69 [2] b6 78 [2] f8 74 [2] f4 7e [2] e3 75 [2] f8 3b [2] c5 }

  condition:
    any of them
}