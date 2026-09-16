rule TTP_XOR_MULT_DOSStub_cabd {
  strings:
    $key_cabd = { 9e d5 [2] ea cd [2] ad cf [2] ea de [2] a4 d2 [2] a8 d8 [2] bf d3 [2] a4 9d [2] 99 }

  condition:
    any of them
}