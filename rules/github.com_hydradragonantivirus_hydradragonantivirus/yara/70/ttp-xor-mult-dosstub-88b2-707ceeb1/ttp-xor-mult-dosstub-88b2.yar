rule TTP_XOR_MULT_DOSStub_88b2 {
  strings:
    $key_88b2 = { dc da [2] a8 c2 [2] ef c0 [2] a8 d1 [2] e6 dd [2] ea d7 [2] fd dc [2] e6 92 [2] db }

  condition:
    any of them
}