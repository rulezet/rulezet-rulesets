rule TTP_XOR_MULT_DOSStub_24bf {
  strings:
    $key_24bf = { 70 d7 [2] 04 cf [2] 43 cd [2] 04 dc [2] 4a d0 [2] 46 da [2] 51 d1 [2] 4a 9f [2] 77 }

  condition:
    any of them
}