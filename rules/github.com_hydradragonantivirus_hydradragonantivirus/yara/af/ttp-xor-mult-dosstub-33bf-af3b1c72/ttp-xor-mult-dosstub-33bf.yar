rule TTP_XOR_MULT_DOSStub_33bf {
  strings:
    $key_33bf = { 67 d7 [2] 13 cf [2] 54 cd [2] 13 dc [2] 5d d0 [2] 51 da [2] 46 d1 [2] 5d 9f [2] 60 }

  condition:
    any of them
}