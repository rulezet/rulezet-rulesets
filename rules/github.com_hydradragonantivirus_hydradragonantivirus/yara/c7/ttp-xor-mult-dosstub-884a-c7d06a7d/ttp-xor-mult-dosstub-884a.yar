rule TTP_XOR_MULT_DOSStub_884a {
  strings:
    $key_884a = { dc 22 [2] a8 3a [2] ef 38 [2] a8 29 [2] e6 25 [2] ea 2f [2] fd 24 [2] e6 6a [2] db }

  condition:
    any of them
}