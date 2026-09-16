rule TTP_XOR_MULT_DOSStub_50bf {
  strings:
    $key_50bf = { 04 d7 [2] 70 cf [2] 37 cd [2] 70 dc [2] 3e d0 [2] 32 da [2] 25 d1 [2] 3e 9f [2] 03 }

  condition:
    any of them
}