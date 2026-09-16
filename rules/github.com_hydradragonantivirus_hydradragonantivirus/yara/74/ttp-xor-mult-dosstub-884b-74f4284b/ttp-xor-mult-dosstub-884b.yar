rule TTP_XOR_MULT_DOSStub_884b {
  strings:
    $key_884b = { dc 23 [2] a8 3b [2] ef 39 [2] a8 28 [2] e6 24 [2] ea 2e [2] fd 25 [2] e6 6b [2] db }

  condition:
    any of them
}