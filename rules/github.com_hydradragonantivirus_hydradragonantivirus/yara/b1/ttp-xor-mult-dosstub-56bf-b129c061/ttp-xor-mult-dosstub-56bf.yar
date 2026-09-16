rule TTP_XOR_MULT_DOSStub_56bf {
  strings:
    $key_56bf = { 02 d7 [2] 76 cf [2] 31 cd [2] 76 dc [2] 38 d0 [2] 34 da [2] 23 d1 [2] 38 9f [2] 05 }

  condition:
    any of them
}