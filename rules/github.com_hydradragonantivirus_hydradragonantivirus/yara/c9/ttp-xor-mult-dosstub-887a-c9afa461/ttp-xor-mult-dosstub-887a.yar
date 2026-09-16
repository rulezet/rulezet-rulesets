rule TTP_XOR_MULT_DOSStub_887a {
  strings:
    $key_887a = { dc 12 [2] a8 0a [2] ef 08 [2] a8 19 [2] e6 15 [2] ea 1f [2] fd 14 [2] e6 5a [2] db }

  condition:
    any of them
}