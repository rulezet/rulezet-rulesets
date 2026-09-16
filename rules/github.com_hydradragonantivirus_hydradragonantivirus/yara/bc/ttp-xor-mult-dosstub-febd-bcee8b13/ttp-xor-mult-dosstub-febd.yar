rule TTP_XOR_MULT_DOSStub_febd {
  strings:
    $key_febd = { aa d5 [2] de cd [2] 99 cf [2] de de [2] 90 d2 [2] 9c d8 [2] 8b d3 [2] 90 9d [2] ad }

  condition:
    any of them
}