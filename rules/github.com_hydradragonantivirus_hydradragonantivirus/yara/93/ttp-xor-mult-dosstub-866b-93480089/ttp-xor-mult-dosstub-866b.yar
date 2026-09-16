rule TTP_XOR_MULT_DOSStub_866b {
  strings:
    $key_866b = { d2 03 [2] a6 1b [2] e1 19 [2] a6 08 [2] e8 04 [2] e4 0e [2] f3 05 [2] e8 4b [2] d5 }

  condition:
    any of them
}