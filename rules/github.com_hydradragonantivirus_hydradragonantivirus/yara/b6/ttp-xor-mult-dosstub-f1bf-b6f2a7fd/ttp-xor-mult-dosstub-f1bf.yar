rule TTP_XOR_MULT_DOSStub_f1bf {
  strings:
    $key_f1bf = { a5 d7 [2] d1 cf [2] 96 cd [2] d1 dc [2] 9f d0 [2] 93 da [2] 84 d1 [2] 9f 9f [2] a2 }

  condition:
    any of them
}