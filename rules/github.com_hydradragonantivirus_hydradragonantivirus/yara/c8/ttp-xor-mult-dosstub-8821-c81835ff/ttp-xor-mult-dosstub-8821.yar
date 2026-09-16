rule TTP_XOR_MULT_DOSStub_8821 {
  strings:
    $key_8821 = { dc 49 [2] a8 51 [2] ef 53 [2] a8 42 [2] e6 4e [2] ea 44 [2] fd 4f [2] e6 01 [2] db }

  condition:
    any of them
}