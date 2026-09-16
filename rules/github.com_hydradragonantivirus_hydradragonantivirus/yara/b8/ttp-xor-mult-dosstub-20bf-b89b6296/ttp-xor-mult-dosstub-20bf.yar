rule TTP_XOR_MULT_DOSStub_20bf {
  strings:
    $key_20bf = { 74 d7 [2] 00 cf [2] 47 cd [2] 00 dc [2] 4e d0 [2] 42 da [2] 55 d1 [2] 4e 9f [2] 73 }

  condition:
    any of them
}