rule TTP_XOR_MULT_DOSStub_8870 {
  strings:
    $key_8870 = { dc 18 [2] a8 00 [2] ef 02 [2] a8 13 [2] e6 1f [2] ea 15 [2] fd 1e [2] e6 50 [2] db }

  condition:
    any of them
}