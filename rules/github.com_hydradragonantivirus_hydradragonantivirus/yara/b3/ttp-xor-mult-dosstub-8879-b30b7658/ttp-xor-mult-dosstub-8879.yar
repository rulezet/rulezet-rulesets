rule TTP_XOR_MULT_DOSStub_8879 {
  strings:
    $key_8879 = { dc 11 [2] a8 09 [2] ef 0b [2] a8 1a [2] e6 16 [2] ea 1c [2] fd 17 [2] e6 59 [2] db }

  condition:
    any of them
}