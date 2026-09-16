rule TTP_XOR_MULT_DOSStub_8827 {
  strings:
    $key_8827 = { dc 4f [2] a8 57 [2] ef 55 [2] a8 44 [2] e6 48 [2] ea 42 [2] fd 49 [2] e6 07 [2] db }

  condition:
    any of them
}