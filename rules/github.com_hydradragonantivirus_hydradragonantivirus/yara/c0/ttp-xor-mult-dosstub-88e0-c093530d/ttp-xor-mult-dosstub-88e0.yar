rule TTP_XOR_MULT_DOSStub_88e0 {
  strings:
    $key_88e0 = { dc 88 [2] a8 90 [2] ef 92 [2] a8 83 [2] e6 8f [2] ea 85 [2] fd 8e [2] e6 c0 [2] db }

  condition:
    any of them
}