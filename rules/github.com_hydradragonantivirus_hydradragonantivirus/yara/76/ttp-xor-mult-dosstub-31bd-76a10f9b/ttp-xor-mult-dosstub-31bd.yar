rule TTP_XOR_MULT_DOSStub_31bd {
  strings:
    $key_31bd = { 65 d5 [2] 11 cd [2] 56 cf [2] 11 de [2] 5f d2 [2] 53 d8 [2] 44 d3 [2] 5f 9d [2] 62 }

  condition:
    any of them
}