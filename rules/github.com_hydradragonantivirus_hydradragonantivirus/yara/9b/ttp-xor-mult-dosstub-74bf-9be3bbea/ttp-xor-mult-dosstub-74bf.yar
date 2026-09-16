rule TTP_XOR_MULT_DOSStub_74bf {
  strings:
    $key_74bf = { 20 d7 [2] 54 cf [2] 13 cd [2] 54 dc [2] 1a d0 [2] 16 da [2] 01 d1 [2] 1a 9f [2] 27 }

  condition:
    any of them
}