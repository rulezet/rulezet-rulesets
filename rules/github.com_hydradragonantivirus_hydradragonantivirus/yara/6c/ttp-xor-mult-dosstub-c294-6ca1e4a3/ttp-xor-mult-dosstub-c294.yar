rule TTP_XOR_MULT_DOSStub_c294 {
  strings:
    $key_c294 = { 96 fc [2] e2 e4 [2] a5 e6 [2] e2 f7 [2] ac fb [2] a0 f1 [2] b7 fa [2] ac b4 [2] 91 }

  condition:
    any of them
}