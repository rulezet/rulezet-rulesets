rule TTP_XOR_MULT_DOSStub_06bf {
  strings:
    $key_06bf = { 52 d7 [2] 26 cf [2] 61 cd [2] 26 dc [2] 68 d0 [2] 64 da [2] 73 d1 [2] 68 9f [2] 55 }

  condition:
    any of them
}