rule TTP_XOR_MULT_DOSStub_81bf {
  strings:
    $key_81bf = { d5 d7 [2] a1 cf [2] e6 cd [2] a1 dc [2] ef d0 [2] e3 da [2] f4 d1 [2] ef 9f [2] d2 }

  condition:
    any of them
}