rule TTP_XOR_MULT_DOSStub_8601 {
  strings:
    $key_8601 = { d2 69 [2] a6 71 [2] e1 73 [2] a6 62 [2] e8 6e [2] e4 64 [2] f3 6f [2] e8 21 [2] d5 }

  condition:
    any of them
}