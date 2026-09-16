rule TTP_XOR_MULT_DOSStub_8853 {
  strings:
    $key_8853 = { dc 3b [2] a8 23 [2] ef 21 [2] a8 30 [2] e6 3c [2] ea 36 [2] fd 3d [2] e6 73 [2] db }

  condition:
    any of them
}