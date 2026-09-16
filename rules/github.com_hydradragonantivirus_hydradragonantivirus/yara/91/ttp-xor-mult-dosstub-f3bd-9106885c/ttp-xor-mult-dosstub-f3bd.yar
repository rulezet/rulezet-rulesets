rule TTP_XOR_MULT_DOSStub_f3bd {
  strings:
    $key_f3bd = { a7 d5 [2] d3 cd [2] 94 cf [2] d3 de [2] 9d d2 [2] 91 d8 [2] 86 d3 [2] 9d 9d [2] a0 }

  condition:
    any of them
}