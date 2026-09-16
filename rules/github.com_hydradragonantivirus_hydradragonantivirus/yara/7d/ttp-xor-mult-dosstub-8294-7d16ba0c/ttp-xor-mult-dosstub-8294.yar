rule TTP_XOR_MULT_DOSStub_8294 {
  strings:
    $key_8294 = { d6 fc [2] a2 e4 [2] e5 e6 [2] a2 f7 [2] ec fb [2] e0 f1 [2] f7 fa [2] ec b4 [2] d1 }

  condition:
    any of them
}