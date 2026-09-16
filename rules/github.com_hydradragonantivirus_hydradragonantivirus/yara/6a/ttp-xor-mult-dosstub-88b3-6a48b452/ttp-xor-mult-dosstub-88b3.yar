rule TTP_XOR_MULT_DOSStub_88b3 {
  strings:
    $key_88b3 = { dc db [2] a8 c3 [2] ef c1 [2] a8 d0 [2] e6 dc [2] ea d6 [2] fd dd [2] e6 93 [2] db }

  condition:
    any of them
}