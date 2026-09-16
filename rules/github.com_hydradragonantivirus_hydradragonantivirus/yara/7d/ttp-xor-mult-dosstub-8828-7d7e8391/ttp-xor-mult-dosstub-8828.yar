rule TTP_XOR_MULT_DOSStub_8828 {
  strings:
    $key_8828 = { dc 40 [2] a8 58 [2] ef 5a [2] a8 4b [2] e6 47 [2] ea 4d [2] fd 46 [2] e6 08 [2] db }

  condition:
    any of them
}