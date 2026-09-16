rule TTP_XOR_MULT_DOSStub_87f8 {
  strings:
    $key_87f8 = { d3 90 [2] a7 88 [2] e0 8a [2] a7 9b [2] e9 97 [2] e5 9d [2] f2 96 [2] e9 d8 [2] d4 }

  condition:
    any of them
}