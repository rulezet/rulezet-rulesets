rule TTP_XOR_MULT_DOSStub_b2bf {
  strings:
    $key_b2bf = { e6 d7 [2] 92 cf [2] d5 cd [2] 92 dc [2] dc d0 [2] d0 da [2] c7 d1 [2] dc 9f [2] e1 }

  condition:
    any of them
}