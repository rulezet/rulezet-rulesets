rule TTP_XOR_MULT_DOSStub_882a {
  strings:
    $key_882a = { dc 42 [2] a8 5a [2] ef 58 [2] a8 49 [2] e6 45 [2] ea 4f [2] fd 44 [2] e6 0a [2] db }

  condition:
    any of them
}