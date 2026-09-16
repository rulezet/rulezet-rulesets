rule TTP_XOR_MULT_DOSStub_887f {
  strings:
    $key_887f = { dc 17 [2] a8 0f [2] ef 0d [2] a8 1c [2] e6 10 [2] ea 1a [2] fd 11 [2] e6 5f [2] db }

  condition:
    any of them
}