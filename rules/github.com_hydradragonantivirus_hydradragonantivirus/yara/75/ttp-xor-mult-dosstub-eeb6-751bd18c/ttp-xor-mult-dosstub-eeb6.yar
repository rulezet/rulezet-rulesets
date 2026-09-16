rule TTP_XOR_MULT_DOSStub_eeb6 {
  strings:
    $key_eeb6 = { ba de [2] ce c6 [2] 89 c4 [2] ce d5 [2] 80 d9 [2] 8c d3 [2] 9b d8 [2] 80 96 [2] bd }

  condition:
    any of them
}