rule TTP_XOR_MULT_DOSStub_8847 {
  strings:
    $key_8847 = { dc 2f [2] a8 37 [2] ef 35 [2] a8 24 [2] e6 28 [2] ea 22 [2] fd 29 [2] e6 67 [2] db }

  condition:
    any of them
}