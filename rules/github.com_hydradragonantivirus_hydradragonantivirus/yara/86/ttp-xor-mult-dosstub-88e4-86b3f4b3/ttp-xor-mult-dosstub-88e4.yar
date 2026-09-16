rule TTP_XOR_MULT_DOSStub_88e4 {
  strings:
    $key_88e4 = { dc 8c [2] a8 94 [2] ef 96 [2] a8 87 [2] e6 8b [2] ea 81 [2] fd 8a [2] e6 c4 [2] db }

  condition:
    any of them
}