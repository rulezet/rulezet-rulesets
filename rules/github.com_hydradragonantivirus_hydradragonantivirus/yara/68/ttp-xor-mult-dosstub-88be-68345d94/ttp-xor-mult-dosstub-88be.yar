rule TTP_XOR_MULT_DOSStub_88be {
  strings:
    $key_88be = { dc d6 [2] a8 ce [2] ef cc [2] a8 dd [2] e6 d1 [2] ea db [2] fd d0 [2] e6 9e [2] db }

  condition:
    any of them
}