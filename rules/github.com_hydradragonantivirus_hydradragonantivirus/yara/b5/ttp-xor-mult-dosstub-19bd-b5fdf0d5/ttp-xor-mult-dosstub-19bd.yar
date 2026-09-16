rule TTP_XOR_MULT_DOSStub_19bd {
  strings:
    $key_19bd = { 4d d5 [2] 39 cd [2] 7e cf [2] 39 de [2] 77 d2 [2] 7b d8 [2] 6c d3 [2] 77 9d [2] 4a }

  condition:
    any of them
}