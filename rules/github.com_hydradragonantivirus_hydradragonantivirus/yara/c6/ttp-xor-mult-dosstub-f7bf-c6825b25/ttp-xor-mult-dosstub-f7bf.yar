rule TTP_XOR_MULT_DOSStub_f7bf {
  strings:
    $key_f7bf = { a3 d7 [2] d7 cf [2] 90 cd [2] d7 dc [2] 99 d0 [2] 95 da [2] 82 d1 [2] 99 9f [2] a4 }

  condition:
    any of them
}