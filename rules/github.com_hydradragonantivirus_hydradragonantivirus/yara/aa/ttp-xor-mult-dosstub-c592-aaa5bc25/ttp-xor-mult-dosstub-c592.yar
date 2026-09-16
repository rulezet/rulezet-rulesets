rule TTP_XOR_MULT_DOSStub_c592 {
  strings:
    $key_c592 = { 91 fa [2] e5 e2 [2] a2 e0 [2] e5 f1 [2] ab fd [2] a7 f7 [2] b0 fc [2] ab b2 [2] 96 }

  condition:
    any of them
}