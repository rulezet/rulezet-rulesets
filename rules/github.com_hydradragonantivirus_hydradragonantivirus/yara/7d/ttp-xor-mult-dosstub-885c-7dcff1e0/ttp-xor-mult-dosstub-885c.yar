rule TTP_XOR_MULT_DOSStub_885c {
  strings:
    $key_885c = { dc 34 [2] a8 2c [2] ef 2e [2] a8 3f [2] e6 33 [2] ea 39 [2] fd 32 [2] e6 7c [2] db }

  condition:
    any of them
}