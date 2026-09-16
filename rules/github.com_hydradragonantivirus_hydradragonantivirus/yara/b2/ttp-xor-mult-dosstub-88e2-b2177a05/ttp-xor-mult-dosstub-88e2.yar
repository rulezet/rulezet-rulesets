rule TTP_XOR_MULT_DOSStub_88e2 {
  strings:
    $key_88e2 = { dc 8a [2] a8 92 [2] ef 90 [2] a8 81 [2] e6 8d [2] ea 87 [2] fd 8c [2] e6 c2 [2] db }

  condition:
    any of them
}