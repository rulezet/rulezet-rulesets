rule TTP_XOR_MULT_DOSStub_c5bd {
  strings:
    $key_c5bd = { 91 d5 [2] e5 cd [2] a2 cf [2] e5 de [2] ab d2 [2] a7 d8 [2] b0 d3 [2] ab 9d [2] 96 }

  condition:
    any of them
}