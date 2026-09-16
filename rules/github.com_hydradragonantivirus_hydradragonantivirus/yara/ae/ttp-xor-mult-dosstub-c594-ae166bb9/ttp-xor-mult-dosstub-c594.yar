rule TTP_XOR_MULT_DOSStub_c594 {
  strings:
    $key_c594 = { 91 fc [2] e5 e4 [2] a2 e6 [2] e5 f7 [2] ab fb [2] a7 f1 [2] b0 fa [2] ab b4 [2] 96 }

  condition:
    any of them
}