rule TTP_XOR_MULT_DOSStub_8830 {
  strings:
    $key_8830 = { dc 58 [2] a8 40 [2] ef 42 [2] a8 53 [2] e6 5f [2] ea 55 [2] fd 5e [2] e6 10 [2] db }

  condition:
    any of them
}