rule TTP_XOR_MULT_DOSStub_03bd {
  strings:
    $key_03bd = { 57 d5 [2] 23 cd [2] 64 cf [2] 23 de [2] 6d d2 [2] 61 d8 [2] 76 d3 [2] 6d 9d [2] 50 }

  condition:
    any of them
}