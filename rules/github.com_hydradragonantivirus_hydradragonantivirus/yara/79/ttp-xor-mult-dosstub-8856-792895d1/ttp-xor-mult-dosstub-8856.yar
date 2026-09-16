rule TTP_XOR_MULT_DOSStub_8856 {
  strings:
    $key_8856 = { dc 3e [2] a8 26 [2] ef 24 [2] a8 35 [2] e6 39 [2] ea 33 [2] fd 38 [2] e6 76 [2] db }

  condition:
    any of them
}