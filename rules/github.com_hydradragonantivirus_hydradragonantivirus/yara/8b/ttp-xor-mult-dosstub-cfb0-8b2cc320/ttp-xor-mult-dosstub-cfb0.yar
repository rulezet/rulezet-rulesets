rule TTP_XOR_MULT_DOSStub_cfb0 {
  strings:
    $key_cfb0 = { 9b d8 [2] ef c0 [2] a8 c2 [2] ef d3 [2] a1 df [2] ad d5 [2] ba de [2] a1 90 [2] 9c }

  condition:
    any of them
}