rule TTP_XOR_MULT_DOSStub_73bf {
  strings:
    $key_73bf = { 27 d7 [2] 53 cf [2] 14 cd [2] 53 dc [2] 1d d0 [2] 11 da [2] 06 d1 [2] 1d 9f [2] 20 }

  condition:
    any of them
}