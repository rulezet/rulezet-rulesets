rule TTP_XOR_MULT_DOSStub_0dbd {
  strings:
    $key_0dbd = { 59 d5 [2] 2d cd [2] 6a cf [2] 2d de [2] 63 d2 [2] 6f d8 [2] 78 d3 [2] 63 9d [2] 5e }

  condition:
    any of them
}