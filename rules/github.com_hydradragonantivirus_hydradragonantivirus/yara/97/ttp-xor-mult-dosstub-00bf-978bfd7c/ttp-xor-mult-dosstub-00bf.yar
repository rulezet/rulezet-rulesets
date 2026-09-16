rule TTP_XOR_MULT_DOSStub_00bf {
  strings:
    $key_00bf = { 54 d7 [2] 20 cf [2] 67 cd [2] 20 dc [2] 6e d0 [2] 62 da [2] 75 d1 [2] 6e 9f [2] 53 }

  condition:
    any of them
}