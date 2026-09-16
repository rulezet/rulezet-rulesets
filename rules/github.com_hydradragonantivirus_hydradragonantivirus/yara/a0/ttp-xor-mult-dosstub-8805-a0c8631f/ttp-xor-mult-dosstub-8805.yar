rule TTP_XOR_MULT_DOSStub_8805 {
  strings:
    $key_8805 = { dc 6d [2] a8 75 [2] ef 77 [2] a8 66 [2] e6 6a [2] ea 60 [2] fd 6b [2] e6 25 [2] db }

  condition:
    any of them
}