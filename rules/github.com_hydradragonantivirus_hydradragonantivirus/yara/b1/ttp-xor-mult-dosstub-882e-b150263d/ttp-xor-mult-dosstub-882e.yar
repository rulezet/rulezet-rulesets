rule TTP_XOR_MULT_DOSStub_882e {
  strings:
    $key_882e = { dc 46 [2] a8 5e [2] ef 5c [2] a8 4d [2] e6 41 [2] ea 4b [2] fd 40 [2] e6 0e [2] db }

  condition:
    any of them
}