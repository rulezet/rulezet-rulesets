rule TTP_XOR_MULT_DOSStub_52bf {
  strings:
    $key_52bf = { 06 d7 [2] 72 cf [2] 35 cd [2] 72 dc [2] 3c d0 [2] 30 da [2] 27 d1 [2] 3c 9f [2] 01 }

  condition:
    any of them
}