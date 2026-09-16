rule TTP_XOR_MULT_DOSStub_88c5 {
  strings:
    $key_88c5 = { dc ad [2] a8 b5 [2] ef b7 [2] a8 a6 [2] e6 aa [2] ea a0 [2] fd ab [2] e6 e5 [2] db }

  condition:
    any of them
}