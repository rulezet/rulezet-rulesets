rule TTP_XOR_MULT_DOSStub_c4bd {
  strings:
    $key_c4bd = { 90 d5 [2] e4 cd [2] a3 cf [2] e4 de [2] aa d2 [2] a6 d8 [2] b1 d3 [2] aa 9d [2] 97 }

  condition:
    any of them
}