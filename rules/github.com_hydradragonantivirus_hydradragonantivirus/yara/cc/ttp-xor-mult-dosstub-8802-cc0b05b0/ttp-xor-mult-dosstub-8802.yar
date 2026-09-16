rule TTP_XOR_MULT_DOSStub_8802 {
  strings:
    $key_8802 = { dc 6a [2] a8 72 [2] ef 70 [2] a8 61 [2] e6 6d [2] ea 67 [2] fd 6c [2] e6 22 [2] db }

  condition:
    any of them
}