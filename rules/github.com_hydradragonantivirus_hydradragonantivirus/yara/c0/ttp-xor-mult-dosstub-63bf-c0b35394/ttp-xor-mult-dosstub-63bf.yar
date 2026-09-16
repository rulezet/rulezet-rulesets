rule TTP_XOR_MULT_DOSStub_63bf {
  strings:
    $key_63bf = { 37 d7 [2] 43 cf [2] 04 cd [2] 43 dc [2] 0d d0 [2] 01 da [2] 16 d1 [2] 0d 9f [2] 30 }

  condition:
    any of them
}