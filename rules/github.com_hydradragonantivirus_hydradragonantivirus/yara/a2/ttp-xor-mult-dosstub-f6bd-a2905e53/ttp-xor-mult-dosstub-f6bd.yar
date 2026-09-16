rule TTP_XOR_MULT_DOSStub_f6bd {
  strings:
    $key_f6bd = { a2 d5 [2] d6 cd [2] 91 cf [2] d6 de [2] 98 d2 [2] 94 d8 [2] 83 d3 [2] 98 9d [2] a5 }

  condition:
    any of them
}