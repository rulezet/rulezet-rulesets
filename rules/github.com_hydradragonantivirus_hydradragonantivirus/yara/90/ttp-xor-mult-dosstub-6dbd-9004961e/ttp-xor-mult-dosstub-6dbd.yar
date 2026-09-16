rule TTP_XOR_MULT_DOSStub_6dbd {
  strings:
    $key_6dbd = { 39 d5 [2] 4d cd [2] 0a cf [2] 4d de [2] 03 d2 [2] 0f d8 [2] 18 d3 [2] 03 9d [2] 3e }

  condition:
    any of them
}