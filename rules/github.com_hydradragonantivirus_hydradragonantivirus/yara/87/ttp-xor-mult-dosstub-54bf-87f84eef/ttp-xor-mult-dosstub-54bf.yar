rule TTP_XOR_MULT_DOSStub_54bf {
  strings:
    $key_54bf = { 00 d7 [2] 74 cf [2] 33 cd [2] 74 dc [2] 3a d0 [2] 36 da [2] 21 d1 [2] 3a 9f [2] 07 }

  condition:
    any of them
}