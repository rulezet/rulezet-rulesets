rule TTP_XOR_MULT_DOSStub_8875 {
  strings:
    $key_8875 = { dc 1d [2] a8 05 [2] ef 07 [2] a8 16 [2] e6 1a [2] ea 10 [2] fd 1b [2] e6 55 [2] db }

  condition:
    any of them
}