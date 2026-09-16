rule TTP_XOR_MULT_DOSStub_8808 {
  strings:
    $key_8808 = { dc 60 [2] a8 78 [2] ef 7a [2] a8 6b [2] e6 67 [2] ea 6d [2] fd 66 [2] e6 28 [2] db }

  condition:
    any of them
}