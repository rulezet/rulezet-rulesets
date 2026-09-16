rule TTP_XOR_MULT_DOSStub_8833 {
  strings:
    $key_8833 = { dc 5b [2] a8 43 [2] ef 41 [2] a8 50 [2] e6 5c [2] ea 56 [2] fd 5d [2] e6 13 [2] db }

  condition:
    any of them
}