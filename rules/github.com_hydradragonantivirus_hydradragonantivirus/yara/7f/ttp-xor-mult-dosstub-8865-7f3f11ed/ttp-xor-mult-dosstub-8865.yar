rule TTP_XOR_MULT_DOSStub_8865 {
  strings:
    $key_8865 = { dc 0d [2] a8 15 [2] ef 17 [2] a8 06 [2] e6 0a [2] ea 00 [2] fd 0b [2] e6 45 [2] db }

  condition:
    any of them
}