rule TTP_XOR_MULT_DOSStub_8878 {
  strings:
    $key_8878 = { dc 10 [2] a8 08 [2] ef 0a [2] a8 1b [2] e6 17 [2] ea 1d [2] fd 16 [2] e6 58 [2] db }

  condition:
    any of them
}