rule TTP_XOR_MULT_DOSStub_8860 {
  strings:
    $key_8860 = { dc 08 [2] a8 10 [2] ef 12 [2] a8 03 [2] e6 0f [2] ea 05 [2] fd 0e [2] e6 40 [2] db }

  condition:
    any of them
}