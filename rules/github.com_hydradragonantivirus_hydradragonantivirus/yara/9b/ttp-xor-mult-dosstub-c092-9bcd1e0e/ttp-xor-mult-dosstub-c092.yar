rule TTP_XOR_MULT_DOSStub_c092 {
  strings:
    $key_c092 = { 94 fa [2] e0 e2 [2] a7 e0 [2] e0 f1 [2] ae fd [2] a2 f7 [2] b5 fc [2] ae b2 [2] 93 }

  condition:
    any of them
}