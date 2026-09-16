rule TTP_XOR_MULT_DOSStub_8807 {
  strings:
    $key_8807 = { dc 6f [2] a8 77 [2] ef 75 [2] a8 64 [2] e6 68 [2] ea 62 [2] fd 69 [2] e6 27 [2] db }

  condition:
    any of them
}