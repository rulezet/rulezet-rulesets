rule TTP_XOR_MULT_DOSStub_884e {
  strings:
    $key_884e = { dc 26 [2] a8 3e [2] ef 3c [2] a8 2d [2] e6 21 [2] ea 2b [2] fd 20 [2] e6 6e [2] db }

  condition:
    any of them
}