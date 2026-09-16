rule TTP_XOR_MULT_DOSStub_f2bf {
  strings:
    $key_f2bf = { a6 d7 [2] d2 cf [2] 95 cd [2] d2 dc [2] 9c d0 [2] 90 da [2] 87 d1 [2] 9c 9f [2] a1 }

  condition:
    any of them
}