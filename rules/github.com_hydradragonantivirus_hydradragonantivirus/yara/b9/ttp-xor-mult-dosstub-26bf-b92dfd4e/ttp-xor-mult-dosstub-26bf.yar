rule TTP_XOR_MULT_DOSStub_26bf {
  strings:
    $key_26bf = { 72 d7 [2] 06 cf [2] 41 cd [2] 06 dc [2] 48 d0 [2] 44 da [2] 53 d1 [2] 48 9f [2] 75 }

  condition:
    any of them
}