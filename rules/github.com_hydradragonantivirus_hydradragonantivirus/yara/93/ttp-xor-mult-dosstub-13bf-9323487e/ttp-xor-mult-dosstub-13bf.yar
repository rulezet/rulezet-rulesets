rule TTP_XOR_MULT_DOSStub_13bf {
  strings:
    $key_13bf = { 47 d7 [2] 33 cf [2] 74 cd [2] 33 dc [2] 7d d0 [2] 71 da [2] 66 d1 [2] 7d 9f [2] 40 }

  condition:
    any of them
}