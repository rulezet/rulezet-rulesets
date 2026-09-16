rule TTP_XOR_MULT_DOSStub_8852 {
  strings:
    $key_8852 = { dc 3a [2] a8 22 [2] ef 20 [2] a8 31 [2] e6 3d [2] ea 37 [2] fd 3c [2] e6 72 [2] db }

  condition:
    any of them
}