rule TTP_XOR_MULT_DOSStub_e5bf {
  strings:
    $key_e5bf = { b1 d7 [2] c5 cf [2] 82 cd [2] c5 dc [2] 8b d0 [2] 87 da [2] 90 d1 [2] 8b 9f [2] b6 }

  condition:
    any of them
}