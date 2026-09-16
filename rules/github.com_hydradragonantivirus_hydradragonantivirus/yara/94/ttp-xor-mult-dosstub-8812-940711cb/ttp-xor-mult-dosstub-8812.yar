rule TTP_XOR_MULT_DOSStub_8812 {
  strings:
    $key_8812 = { dc 7a [2] a8 62 [2] ef 60 [2] a8 71 [2] e6 7d [2] ea 77 [2] fd 7c [2] e6 32 [2] db }

  condition:
    any of them
}