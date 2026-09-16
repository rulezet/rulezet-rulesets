rule TTP_XOR_MULT_DOSStub_88b0 {
  strings:
    $key_88b0 = { dc d8 [2] a8 c0 [2] ef c2 [2] a8 d3 [2] e6 df [2] ea d5 [2] fd de [2] e6 90 [2] db }

  condition:
    any of them
}