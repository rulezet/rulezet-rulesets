rule TTP_XOR_MULT_DOSStub_87e0 {
  strings:
    $key_87e0 = { d3 88 [2] a7 90 [2] e0 92 [2] a7 83 [2] e9 8f [2] e5 85 [2] f2 8e [2] e9 c0 [2] d4 }

  condition:
    any of them
}