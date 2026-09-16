rule TTP_XOR_MULT_DOSStub_eebd {
  strings:
    $key_eebd = { ba d5 [2] ce cd [2] 89 cf [2] ce de [2] 80 d2 [2] 8c d8 [2] 9b d3 [2] 80 9d [2] bd }

  condition:
    any of them
}