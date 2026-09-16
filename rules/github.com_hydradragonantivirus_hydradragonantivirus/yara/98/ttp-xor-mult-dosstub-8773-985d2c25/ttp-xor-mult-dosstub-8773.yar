rule TTP_XOR_MULT_DOSStub_8773 {
  strings:
    $key_8773 = { d3 1b [2] a7 03 [2] e0 01 [2] a7 10 [2] e9 1c [2] e5 16 [2] f2 1d [2] e9 53 [2] d4 }

  condition:
    any of them
}