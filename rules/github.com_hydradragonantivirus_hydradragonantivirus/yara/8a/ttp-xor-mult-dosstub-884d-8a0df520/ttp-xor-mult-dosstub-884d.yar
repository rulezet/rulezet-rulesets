rule TTP_XOR_MULT_DOSStub_884d {
  strings:
    $key_884d = { dc 25 [2] a8 3d [2] ef 3f [2] a8 2e [2] e6 22 [2] ea 28 [2] fd 23 [2] e6 6d [2] db }

  condition:
    any of them
}