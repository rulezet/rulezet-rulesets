rule TTP_XOR_MULT_DOSStub_88f1 {
  strings:
    $key_88f1 = { dc 99 [2] a8 81 [2] ef 83 [2] a8 92 [2] e6 9e [2] ea 94 [2] fd 9f [2] e6 d1 [2] db }

  condition:
    any of them
}