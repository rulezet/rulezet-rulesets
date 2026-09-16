rule TTP_XOR_MULT_DOSStub_88f2 {
  strings:
    $key_88f2 = { dc 9a [2] a8 82 [2] ef 80 [2] a8 91 [2] e6 9d [2] ea 97 [2] fd 9c [2] e6 d2 [2] db }

  condition:
    any of them
}