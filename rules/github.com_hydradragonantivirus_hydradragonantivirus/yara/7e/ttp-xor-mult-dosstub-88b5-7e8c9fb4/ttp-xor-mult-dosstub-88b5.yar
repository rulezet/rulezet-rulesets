rule TTP_XOR_MULT_DOSStub_88b5 {
  strings:
    $key_88b5 = { dc dd [2] a8 c5 [2] ef c7 [2] a8 d6 [2] e6 da [2] ea d0 [2] fd db [2] e6 95 [2] db }

  condition:
    any of them
}