rule TTP_XOR_MULT_DOSStub_8872 {
  strings:
    $key_8872 = { dc 1a [2] a8 02 [2] ef 00 [2] a8 11 [2] e6 1d [2] ea 17 [2] fd 1c [2] e6 52 [2] db }

  condition:
    any of them
}