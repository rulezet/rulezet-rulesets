rule TTP_XOR_MULT_DOSStub_87e8 {
  strings:
    $key_87e8 = { d3 80 [2] a7 98 [2] e0 9a [2] a7 8b [2] e9 87 [2] e5 8d [2] f2 86 [2] e9 c8 [2] d4 }

  condition:
    any of them
}