rule TTP_XOR_MULT_DOSStub_bfbd {
  strings:
    $key_bfbd = { eb d5 [2] 9f cd [2] d8 cf [2] 9f de [2] d1 d2 [2] dd d8 [2] ca d3 [2] d1 9d [2] ec }

  condition:
    any of them
}