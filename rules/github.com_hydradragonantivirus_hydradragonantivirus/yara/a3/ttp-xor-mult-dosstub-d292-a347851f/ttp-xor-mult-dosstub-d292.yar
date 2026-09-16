rule TTP_XOR_MULT_DOSStub_d292 {
  strings:
    $key_d292 = { 86 fa [2] f2 e2 [2] b5 e0 [2] f2 f1 [2] bc fd [2] b0 f7 [2] a7 fc [2] bc b2 [2] 81 }

  condition:
    any of them
}