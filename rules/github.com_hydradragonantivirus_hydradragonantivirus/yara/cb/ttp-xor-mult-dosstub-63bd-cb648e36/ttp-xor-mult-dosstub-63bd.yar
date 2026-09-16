rule TTP_XOR_MULT_DOSStub_63bd {
  strings:
    $key_63bd = { 37 d5 [2] 43 cd [2] 04 cf [2] 43 de [2] 0d d2 [2] 01 d8 [2] 16 d3 [2] 0d 9d [2] 30 }

  condition:
    any of them
}