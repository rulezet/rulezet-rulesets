rule TTP_XOR_MULT_DOSStub_8099 {
  strings:
    $key_8099 = { d4 f1 [2] a0 e9 [2] e7 eb [2] a0 fa [2] ee f6 [2] e2 fc [2] f5 f7 [2] ee b9 [2] d3 }

  condition:
    any of them
}