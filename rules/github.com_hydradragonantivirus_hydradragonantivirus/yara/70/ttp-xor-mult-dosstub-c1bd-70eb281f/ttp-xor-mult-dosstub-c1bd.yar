rule TTP_XOR_MULT_DOSStub_c1bd {
  strings:
    $key_c1bd = { 95 d5 [2] e1 cd [2] a6 cf [2] e1 de [2] af d2 [2] a3 d8 [2] b4 d3 [2] af 9d [2] 92 }

  condition:
    any of them
}