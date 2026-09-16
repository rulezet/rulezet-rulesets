rule TTP_XOR_MULT_DOSStub_887c {
  strings:
    $key_887c = { dc 14 [2] a8 0c [2] ef 0e [2] a8 1f [2] e6 13 [2] ea 19 [2] fd 12 [2] e6 5c [2] db }

  condition:
    any of them
}