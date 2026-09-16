rule TTP_XOR_MULT_DOSStub_b1bd {
  strings:
    $key_b1bd = { e5 d5 [2] 91 cd [2] d6 cf [2] 91 de [2] df d2 [2] d3 d8 [2] c4 d3 [2] df 9d [2] e2 }

  condition:
    any of them
}