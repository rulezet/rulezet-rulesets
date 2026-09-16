rule TTP_XOR_MULT_DOSStub_8814 {
  strings:
    $key_8814 = { dc 7c [2] a8 64 [2] ef 66 [2] a8 77 [2] e6 7b [2] ea 71 [2] fd 7a [2] e6 34 [2] db }

  condition:
    any of them
}