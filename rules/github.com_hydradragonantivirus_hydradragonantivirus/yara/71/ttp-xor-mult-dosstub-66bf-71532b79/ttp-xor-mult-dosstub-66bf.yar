rule TTP_XOR_MULT_DOSStub_66bf {
  strings:
    $key_66bf = { 32 d7 [2] 46 cf [2] 01 cd [2] 46 dc [2] 08 d0 [2] 04 da [2] 13 d1 [2] 08 9f [2] 35 }

  condition:
    any of them
}