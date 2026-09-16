rule TTP_XOR_MULT_DOSStub_06bd {
  strings:
    $key_06bd = { 52 d5 [2] 26 cd [2] 61 cf [2] 26 de [2] 68 d2 [2] 64 d8 [2] 73 d3 [2] 68 9d [2] 55 }

  condition:
    any of them
}