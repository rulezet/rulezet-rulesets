rule TTP_XOR_MULT_DOSStub_64bf {
  strings:
    $key_64bf = { 30 d7 [2] 44 cf [2] 03 cd [2] 44 dc [2] 0a d0 [2] 06 da [2] 11 d1 [2] 0a 9f [2] 37 }

  condition:
    any of them
}