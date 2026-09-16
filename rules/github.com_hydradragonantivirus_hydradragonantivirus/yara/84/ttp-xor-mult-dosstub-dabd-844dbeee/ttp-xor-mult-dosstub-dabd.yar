rule TTP_XOR_MULT_DOSStub_dabd {
  strings:
    $key_dabd = { 8e d5 [2] fa cd [2] bd cf [2] fa de [2] b4 d2 [2] b8 d8 [2] af d3 [2] b4 9d [2] 89 }

  condition:
    any of them
}