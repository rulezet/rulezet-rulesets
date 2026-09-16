rule TTP_XOR_MULT_DOSStub_87f5 {
  strings:
    $key_87f5 = { d3 9d [2] a7 85 [2] e0 87 [2] a7 96 [2] e9 9a [2] e5 90 [2] f2 9b [2] e9 d5 [2] d4 }

  condition:
    any of them
}