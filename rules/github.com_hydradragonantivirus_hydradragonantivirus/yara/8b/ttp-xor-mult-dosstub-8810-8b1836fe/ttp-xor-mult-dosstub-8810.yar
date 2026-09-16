rule TTP_XOR_MULT_DOSStub_8810 {
  strings:
    $key_8810 = { dc 78 [2] a8 60 [2] ef 62 [2] a8 73 [2] e6 7f [2] ea 75 [2] fd 7e [2] e6 30 [2] db }

  condition:
    any of them
}