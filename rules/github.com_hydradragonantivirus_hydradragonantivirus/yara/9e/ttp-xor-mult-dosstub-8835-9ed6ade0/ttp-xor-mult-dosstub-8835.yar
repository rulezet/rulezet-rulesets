rule TTP_XOR_MULT_DOSStub_8835 {
  strings:
    $key_8835 = { dc 5d [2] a8 45 [2] ef 47 [2] a8 56 [2] e6 5a [2] ea 50 [2] fd 5b [2] e6 15 [2] db }

  condition:
    any of them
}