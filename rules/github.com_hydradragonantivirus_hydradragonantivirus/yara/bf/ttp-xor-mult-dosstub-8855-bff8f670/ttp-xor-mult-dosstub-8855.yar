rule TTP_XOR_MULT_DOSStub_8855 {
  strings:
    $key_8855 = { dc 3d [2] a8 25 [2] ef 27 [2] a8 36 [2] e6 3a [2] ea 30 [2] fd 3b [2] e6 75 [2] db }

  condition:
    any of them
}