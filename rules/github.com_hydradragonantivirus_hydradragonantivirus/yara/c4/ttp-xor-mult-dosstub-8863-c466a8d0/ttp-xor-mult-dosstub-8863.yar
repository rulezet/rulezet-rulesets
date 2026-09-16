rule TTP_XOR_MULT_DOSStub_8863 {
  strings:
    $key_8863 = { dc 0b [2] a8 13 [2] ef 11 [2] a8 00 [2] e6 0c [2] ea 06 [2] fd 0d [2] e6 43 [2] db }

  condition:
    any of them
}