rule TTP_XOR_MULT_DOSStub_cbbd {
  strings:
    $key_cbbd = { 9f d5 [2] eb cd [2] ac cf [2] eb de [2] a5 d2 [2] a9 d8 [2] be d3 [2] a5 9d [2] 98 }

  condition:
    any of them
}