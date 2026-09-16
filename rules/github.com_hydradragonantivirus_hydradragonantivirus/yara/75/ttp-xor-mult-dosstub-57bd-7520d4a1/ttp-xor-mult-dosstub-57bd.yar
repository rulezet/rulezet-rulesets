rule TTP_XOR_MULT_DOSStub_57bd {
  strings:
    $key_57bd = { 03 d5 [2] 77 cd [2] 30 cf [2] 77 de [2] 39 d2 [2] 35 d8 [2] 22 d3 [2] 39 9d [2] 04 }

  condition:
    any of them
}