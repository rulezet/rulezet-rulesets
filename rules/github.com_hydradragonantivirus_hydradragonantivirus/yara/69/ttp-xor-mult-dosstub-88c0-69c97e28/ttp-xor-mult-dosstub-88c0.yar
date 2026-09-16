rule TTP_XOR_MULT_DOSStub_88c0 {
  strings:
    $key_88c0 = { dc a8 [2] a8 b0 [2] ef b2 [2] a8 a3 [2] e6 af [2] ea a5 [2] fd ae [2] e6 e0 [2] db }

  condition:
    any of them
}