rule TTP_XOR_MULT_DOSStub_7dbd {
  strings:
    $key_7dbd = { 29 d5 [2] 5d cd [2] 1a cf [2] 5d de [2] 13 d2 [2] 1f d8 [2] 08 d3 [2] 13 9d [2] 2e }

  condition:
    any of them
}