rule TTP_XOR_MULT_DOSStub_4895 {
  strings:
    $key_4895 = { 1c fd [2] 68 e5 [2] 2f e7 [2] 68 f6 [2] 26 fa [2] 2a f0 [2] 3d fb [2] 26 b5 [2] 1b }

  condition:
    any of them
}