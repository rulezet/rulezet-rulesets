rule TTP_XOR_MULT_DOSStub_88c4 {
  strings:
    $key_88c4 = { dc ac [2] a8 b4 [2] ef b6 [2] a8 a7 [2] e6 ab [2] ea a1 [2] fd aa [2] e6 e4 [2] db }

  condition:
    any of them
}