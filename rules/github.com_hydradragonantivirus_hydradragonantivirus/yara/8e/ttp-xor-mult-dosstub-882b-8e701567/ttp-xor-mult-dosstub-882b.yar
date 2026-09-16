rule TTP_XOR_MULT_DOSStub_882b {
  strings:
    $key_882b = { dc 43 [2] a8 5b [2] ef 59 [2] a8 48 [2] e6 44 [2] ea 4e [2] fd 45 [2] e6 0b [2] db }

  condition:
    any of them
}