rule TTP_XOR_MULT_DOSStub_881d {
  strings:
    $key_881d = { dc 75 [2] a8 6d [2] ef 6f [2] a8 7e [2] e6 72 [2] ea 78 [2] fd 73 [2] e6 3d [2] db }

  condition:
    any of them
}