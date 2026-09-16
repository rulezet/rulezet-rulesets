rule TTP_XOR_MULT_DOSStub_8819 {
  strings:
    $key_8819 = { dc 71 [2] a8 69 [2] ef 6b [2] a8 7a [2] e6 76 [2] ea 7c [2] fd 77 [2] e6 39 [2] db }

  condition:
    any of them
}