rule TTP_XOR_MULT_DOSStub_44bd {
  strings:
    $key_44bd = { 10 d5 [2] 64 cd [2] 23 cf [2] 64 de [2] 2a d2 [2] 26 d8 [2] 31 d3 [2] 2a 9d [2] 17 }

  condition:
    any of them
}