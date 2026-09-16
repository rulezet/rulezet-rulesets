rule TTP_XOR_MULT_DOSStub_e2bd {
  strings:
    $key_e2bd = { b6 d5 [2] c2 cd [2] 85 cf [2] c2 de [2] 8c d2 [2] 80 d8 [2] 97 d3 [2] 8c 9d [2] b1 }

  condition:
    any of them
}