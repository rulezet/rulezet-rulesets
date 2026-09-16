rule TTP_XOR_MULT_DOSStub_27bd {
  strings:
    $key_27bd = { 73 d5 [2] 07 cd [2] 40 cf [2] 07 de [2] 49 d2 [2] 45 d8 [2] 52 d3 [2] 49 9d [2] 74 }

  condition:
    any of them
}