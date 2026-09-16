rule TTP_XOR_MULT_DOSStub_8803 {
  strings:
    $key_8803 = { dc 6b [2] a8 73 [2] ef 71 [2] a8 60 [2] e6 6c [2] ea 66 [2] fd 6d [2] e6 23 [2] db }

  condition:
    any of them
}