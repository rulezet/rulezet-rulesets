rule TTP_XOR_MULT_DOSStub_04bf {
  strings:
    $key_04bf = { 50 d7 [2] 24 cf [2] 63 cd [2] 24 dc [2] 6a d0 [2] 66 da [2] 71 d1 [2] 6a 9f [2] 57 }

  condition:
    any of them
}