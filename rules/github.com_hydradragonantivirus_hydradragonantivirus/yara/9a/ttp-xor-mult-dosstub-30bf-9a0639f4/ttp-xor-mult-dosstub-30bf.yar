rule TTP_XOR_MULT_DOSStub_30bf {
  strings:
    $key_30bf = { 64 d7 [2] 10 cf [2] 57 cd [2] 10 dc [2] 5e d0 [2] 52 da [2] 45 d1 [2] 5e 9f [2] 63 }

  condition:
    any of them
}