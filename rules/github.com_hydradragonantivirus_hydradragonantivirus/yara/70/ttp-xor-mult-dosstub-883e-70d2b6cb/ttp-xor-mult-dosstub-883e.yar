rule TTP_XOR_MULT_DOSStub_883e {
  strings:
    $key_883e = { dc 56 [2] a8 4e [2] ef 4c [2] a8 5d [2] e6 51 [2] ea 5b [2] fd 50 [2] e6 1e [2] db }

  condition:
    any of them
}