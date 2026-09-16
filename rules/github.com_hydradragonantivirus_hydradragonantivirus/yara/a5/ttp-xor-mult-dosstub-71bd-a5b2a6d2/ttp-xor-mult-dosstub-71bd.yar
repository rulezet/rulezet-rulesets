rule TTP_XOR_MULT_DOSStub_71bd {
  strings:
    $key_71bd = { 25 d5 [2] 51 cd [2] 16 cf [2] 51 de [2] 1f d2 [2] 13 d8 [2] 04 d3 [2] 1f 9d [2] 22 }

  condition:
    any of them
}