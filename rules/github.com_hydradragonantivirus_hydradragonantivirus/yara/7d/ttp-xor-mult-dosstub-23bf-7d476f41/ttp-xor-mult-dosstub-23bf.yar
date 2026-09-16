rule TTP_XOR_MULT_DOSStub_23bf {
  strings:
    $key_23bf = { 77 d7 [2] 03 cf [2] 44 cd [2] 03 dc [2] 4d d0 [2] 41 da [2] 56 d1 [2] 4d 9f [2] 70 }

  condition:
    any of them
}