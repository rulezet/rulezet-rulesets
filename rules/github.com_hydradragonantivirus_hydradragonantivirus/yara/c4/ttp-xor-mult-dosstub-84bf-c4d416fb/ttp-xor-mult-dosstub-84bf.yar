rule TTP_XOR_MULT_DOSStub_84bf {
  strings:
    $key_84bf = { d0 d7 [2] a4 cf [2] e3 cd [2] a4 dc [2] ea d0 [2] e6 da [2] f1 d1 [2] ea 9f [2] d7 }

  condition:
    any of them
}