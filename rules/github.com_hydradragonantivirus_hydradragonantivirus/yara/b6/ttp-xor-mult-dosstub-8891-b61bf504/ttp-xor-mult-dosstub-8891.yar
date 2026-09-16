rule TTP_XOR_MULT_DOSStub_8891 {
  strings:
    $key_8891 = { dc f9 [2] a8 e1 [2] ef e3 [2] a8 f2 [2] e6 fe [2] ea f4 [2] fd ff [2] e6 b1 [2] db }

  condition:
    any of them
}