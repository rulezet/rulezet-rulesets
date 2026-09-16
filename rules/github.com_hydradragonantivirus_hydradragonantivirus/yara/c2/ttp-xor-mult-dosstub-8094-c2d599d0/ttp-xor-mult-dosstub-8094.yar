rule TTP_XOR_MULT_DOSStub_8094 {
  strings:
    $key_8094 = { d4 fc [2] a0 e4 [2] e7 e6 [2] a0 f7 [2] ee fb [2] e2 f1 [2] f5 fa [2] ee b4 [2] d3 }

  condition:
    any of them
}