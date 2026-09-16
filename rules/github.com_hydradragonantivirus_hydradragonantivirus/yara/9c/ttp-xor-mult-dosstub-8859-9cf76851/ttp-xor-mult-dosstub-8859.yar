rule TTP_XOR_MULT_DOSStub_8859 {
  strings:
    $key_8859 = { dc 31 [2] a8 29 [2] ef 2b [2] a8 3a [2] e6 36 [2] ea 3c [2] fd 37 [2] e6 79 [2] db }

  condition:
    any of them
}