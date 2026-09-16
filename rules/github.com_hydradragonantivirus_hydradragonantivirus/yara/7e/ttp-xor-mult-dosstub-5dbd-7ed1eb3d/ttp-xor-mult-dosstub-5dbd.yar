rule TTP_XOR_MULT_DOSStub_5dbd {
  strings:
    $key_5dbd = { 09 d5 [2] 7d cd [2] 3a cf [2] 7d de [2] 33 d2 [2] 3f d8 [2] 28 d3 [2] 33 9d [2] 0e }

  condition:
    any of them
}