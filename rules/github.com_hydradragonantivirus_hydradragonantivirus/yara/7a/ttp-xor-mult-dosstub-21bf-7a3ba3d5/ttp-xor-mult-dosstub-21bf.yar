rule TTP_XOR_MULT_DOSStub_21bf {
  strings:
    $key_21bf = { 75 d7 [2] 01 cf [2] 46 cd [2] 01 dc [2] 4f d0 [2] 43 da [2] 54 d1 [2] 4f 9f [2] 72 }

  condition:
    any of them
}