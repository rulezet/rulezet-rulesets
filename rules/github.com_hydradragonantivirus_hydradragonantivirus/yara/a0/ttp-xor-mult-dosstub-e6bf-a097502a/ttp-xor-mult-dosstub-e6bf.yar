rule TTP_XOR_MULT_DOSStub_e6bf {
  strings:
    $key_e6bf = { b2 d7 [2] c6 cf [2] 81 cd [2] c6 dc [2] 88 d0 [2] 84 da [2] 93 d1 [2] 88 9f [2] b5 }

  condition:
    any of them
}