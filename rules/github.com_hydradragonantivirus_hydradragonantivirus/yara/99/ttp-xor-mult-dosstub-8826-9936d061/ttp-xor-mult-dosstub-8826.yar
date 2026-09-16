rule TTP_XOR_MULT_DOSStub_8826 {
  strings:
    $key_8826 = { dc 4e [2] a8 56 [2] ef 54 [2] a8 45 [2] e6 49 [2] ea 43 [2] fd 48 [2] e6 06 [2] db }

  condition:
    any of them
}