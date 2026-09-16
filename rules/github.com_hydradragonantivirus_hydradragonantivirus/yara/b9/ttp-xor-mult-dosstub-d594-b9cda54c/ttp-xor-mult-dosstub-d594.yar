rule TTP_XOR_MULT_DOSStub_d594 {
  strings:
    $key_d594 = { 81 fc [2] f5 e4 [2] b2 e6 [2] f5 f7 [2] bb fb [2] b7 f1 [2] a0 fa [2] bb b4 [2] 86 }

  condition:
    any of them
}