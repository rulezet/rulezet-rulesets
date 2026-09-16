rule TTP_XOR_MULT_DOSStub_87de {
  strings:
    $key_87de = { d3 b6 [2] a7 ae [2] e0 ac [2] a7 bd [2] e9 b1 [2] e5 bb [2] f2 b0 [2] e9 fe [2] d4 }

  condition:
    any of them
}