rule TTP_XOR_MULT_DOSStub_10bf {
  strings:
    $key_10bf = { 44 d7 [2] 30 cf [2] 77 cd [2] 30 dc [2] 7e d0 [2] 72 da [2] 65 d1 [2] 7e 9f [2] 43 }

  condition:
    any of them
}