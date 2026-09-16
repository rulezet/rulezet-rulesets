rule TTP_XOR_MULT_DOSStub_77bf {
  strings:
    $key_77bf = { 23 d7 [2] 57 cf [2] 10 cd [2] 57 dc [2] 19 d0 [2] 15 da [2] 02 d1 [2] 19 9f [2] 24 }

  condition:
    any of them
}