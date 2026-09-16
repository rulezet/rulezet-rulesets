rule TTP_XOR_MULT_DOSStub_880d {
  strings:
    $key_880d = { dc 65 [2] a8 7d [2] ef 7f [2] a8 6e [2] e6 62 [2] ea 68 [2] fd 63 [2] e6 2d [2] db }

  condition:
    any of them
}