rule TTP_XOR_MULT_DOSStub_72bf {
  strings:
    $key_72bf = { 26 d7 [2] 52 cf [2] 15 cd [2] 52 dc [2] 1c d0 [2] 10 da [2] 07 d1 [2] 1c 9f [2] 21 }

  condition:
    any of them
}