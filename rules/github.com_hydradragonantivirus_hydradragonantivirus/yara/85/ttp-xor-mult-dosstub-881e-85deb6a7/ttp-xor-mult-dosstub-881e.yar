rule TTP_XOR_MULT_DOSStub_881e {
  strings:
    $key_881e = { dc 76 [2] a8 6e [2] ef 6c [2] a8 7d [2] e6 71 [2] ea 7b [2] fd 70 [2] e6 3e [2] db }

  condition:
    any of them
}