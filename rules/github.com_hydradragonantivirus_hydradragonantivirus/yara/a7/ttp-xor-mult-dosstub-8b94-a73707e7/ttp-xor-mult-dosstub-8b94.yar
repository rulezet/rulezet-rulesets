rule TTP_XOR_MULT_DOSStub_8b94 {
  strings:
    $key_8b94 = { df fc [2] ab e4 [2] ec e6 [2] ab f7 [2] e5 fb [2] e9 f1 [2] fe fa [2] e5 b4 [2] d8 }

  condition:
    any of them
}