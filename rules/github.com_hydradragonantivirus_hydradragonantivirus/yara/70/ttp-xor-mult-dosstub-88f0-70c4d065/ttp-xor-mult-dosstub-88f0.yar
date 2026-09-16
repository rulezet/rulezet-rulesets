rule TTP_XOR_MULT_DOSStub_88f0 {
  strings:
    $key_88f0 = { dc 98 [2] a8 80 [2] ef 82 [2] a8 93 [2] e6 9f [2] ea 95 [2] fd 9e [2] e6 d0 [2] db }

  condition:
    any of them
}