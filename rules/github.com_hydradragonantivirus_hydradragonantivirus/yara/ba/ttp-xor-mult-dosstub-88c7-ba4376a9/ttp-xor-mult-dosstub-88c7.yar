rule TTP_XOR_MULT_DOSStub_88c7 {
  strings:
    $key_88c7 = { dc af [2] a8 b7 [2] ef b5 [2] a8 a4 [2] e6 a8 [2] ea a2 [2] fd a9 [2] e6 e7 [2] db }

  condition:
    any of them
}