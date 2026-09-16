rule TTP_XOR_MULT_DOSStub_8844 {
  strings:
    $key_8844 = { dc 2c [2] a8 34 [2] ef 36 [2] a8 27 [2] e6 2b [2] ea 21 [2] fd 2a [2] e6 64 [2] db }

  condition:
    any of them
}