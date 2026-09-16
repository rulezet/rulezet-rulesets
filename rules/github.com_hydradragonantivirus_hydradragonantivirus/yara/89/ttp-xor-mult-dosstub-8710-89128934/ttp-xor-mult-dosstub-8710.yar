rule TTP_XOR_MULT_DOSStub_8710 {
  strings:
    $key_8710 = { d3 78 [2] a7 60 [2] e0 62 [2] a7 73 [2] e9 7f [2] e5 75 [2] f2 7e [2] e9 30 [2] d4 }

  condition:
    any of them
}