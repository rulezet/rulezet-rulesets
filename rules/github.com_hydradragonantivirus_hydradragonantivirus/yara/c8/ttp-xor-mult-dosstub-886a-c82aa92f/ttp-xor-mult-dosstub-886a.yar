rule TTP_XOR_MULT_DOSStub_886a {
  strings:
    $key_886a = { dc 02 [2] a8 1a [2] ef 18 [2] a8 09 [2] e6 05 [2] ea 0f [2] fd 04 [2] e6 4a [2] db }

  condition:
    any of them
}