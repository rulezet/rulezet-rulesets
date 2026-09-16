rule TTP_XOR_MULT_DOSStub_cfbd {
  strings:
    $key_cfbd = { 9b d5 [2] ef cd [2] a8 cf [2] ef de [2] a1 d2 [2] ad d8 [2] ba d3 [2] a1 9d [2] 9c }

  condition:
    any of them
}