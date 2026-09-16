rule TTP_XOR_MULT_DOSStub_88fb {
  strings:
    $key_88fb = { dc 93 [2] a8 8b [2] ef 89 [2] a8 98 [2] e6 94 [2] ea 9e [2] fd 95 [2] e6 db [2] db }

  condition:
    any of them
}