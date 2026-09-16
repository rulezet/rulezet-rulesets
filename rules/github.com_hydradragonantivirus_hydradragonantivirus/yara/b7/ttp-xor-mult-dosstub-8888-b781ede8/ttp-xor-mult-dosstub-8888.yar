rule TTP_XOR_MULT_DOSStub_8888 {
  strings:
    $key_8888 = { dc e0 [2] a8 f8 [2] ef fa [2] a8 eb [2] e6 e7 [2] ea ed [2] fd e6 [2] e6 a8 [2] db }

  condition:
    any of them
}