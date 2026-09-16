rule TTP_XOR_MULT_DOSStub_37bd {
  strings:
    $key_37bd = { 63 d5 [2] 17 cd [2] 50 cf [2] 17 de [2] 59 d2 [2] 55 d8 [2] 42 d3 [2] 59 9d [2] 64 }

  condition:
    any of them
}