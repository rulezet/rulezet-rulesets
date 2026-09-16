rule TTP_XOR_MULT_DOSStub_72b0 {
  strings:
    $key_72b0 = { 26 d8 [2] 52 c0 [2] 15 c2 [2] 52 d3 [2] 1c df [2] 10 d5 [2] 07 de [2] 1c 90 [2] 21 }

  condition:
    any of them
}