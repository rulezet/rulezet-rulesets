rule TTP_XOR_MULT_DOSStub_4dbd {
  strings:
    $key_4dbd = { 19 d5 [2] 6d cd [2] 2a cf [2] 6d de [2] 23 d2 [2] 2f d8 [2] 38 d3 [2] 23 9d [2] 1e }

  condition:
    any of them
}