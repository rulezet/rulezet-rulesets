rule TTP_XOR_MULT_DOSStub_8820 {
  strings:
    $key_8820 = { dc 48 [2] a8 50 [2] ef 52 [2] a8 43 [2] e6 4f [2] ea 45 [2] fd 4e [2] e6 00 [2] db }

  condition:
    any of them
}