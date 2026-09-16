rule TTP_XOR_MULT_DOSStub_8845 {
  strings:
    $key_8845 = { dc 2d [2] a8 35 [2] ef 37 [2] a8 26 [2] e6 2a [2] ea 20 [2] fd 2b [2] e6 65 [2] db }

  condition:
    any of them
}