rule TTP_XOR_MULT_DOSStub_938b {
  strings:
    $key_938b = { c7 e3 [2] b3 fb [2] f4 f9 [2] b3 e8 [2] fd e4 [2] f1 ee [2] e6 e5 [2] fd ab [2] c0 }

  condition:
    any of them
}