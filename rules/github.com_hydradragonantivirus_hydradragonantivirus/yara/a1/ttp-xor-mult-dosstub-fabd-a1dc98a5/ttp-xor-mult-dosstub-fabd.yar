rule TTP_XOR_MULT_DOSStub_fabd {
  strings:
    $key_fabd = { ae d5 [2] da cd [2] 9d cf [2] da de [2] 94 d2 [2] 98 d8 [2] 8f d3 [2] 94 9d [2] a9 }

  condition:
    any of them
}