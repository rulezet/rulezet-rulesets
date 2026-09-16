rule TTP_XOR_MULT_DOSStub_3dbd {
  strings:
    $key_3dbd = { 69 d5 [2] 1d cd [2] 5a cf [2] 1d de [2] 53 d2 [2] 5f d8 [2] 48 d3 [2] 53 9d [2] 6e }

  condition:
    any of them
}