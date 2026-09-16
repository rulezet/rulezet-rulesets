rule TTP_XOR_MULT_DOSStub_886d {
  strings:
    $key_886d = { dc 05 [2] a8 1d [2] ef 1f [2] a8 0e [2] e6 02 [2] ea 08 [2] fd 03 [2] e6 4d [2] db }

  condition:
    any of them
}