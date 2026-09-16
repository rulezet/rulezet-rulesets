rule TTP_XOR_MULT_DOSStub_f2bd {
  strings:
    $key_f2bd = { a6 d5 [2] d2 cd [2] 95 cf [2] d2 de [2] 9c d2 [2] 90 d8 [2] 87 d3 [2] 9c 9d [2] a1 }

  condition:
    any of them
}