rule TTP_XOR_MULT_DOSStub_8850 {
  strings:
    $key_8850 = { dc 38 [2] a8 20 [2] ef 22 [2] a8 33 [2] e6 3f [2] ea 35 [2] fd 3e [2] e6 70 [2] db }

  condition:
    any of them
}