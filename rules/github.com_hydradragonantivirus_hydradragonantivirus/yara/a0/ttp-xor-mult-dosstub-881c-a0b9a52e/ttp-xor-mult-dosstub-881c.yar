rule TTP_XOR_MULT_DOSStub_881c {
  strings:
    $key_881c = { dc 74 [2] a8 6c [2] ef 6e [2] a8 7f [2] e6 73 [2] ea 79 [2] fd 72 [2] e6 3c [2] db }

  condition:
    any of them
}