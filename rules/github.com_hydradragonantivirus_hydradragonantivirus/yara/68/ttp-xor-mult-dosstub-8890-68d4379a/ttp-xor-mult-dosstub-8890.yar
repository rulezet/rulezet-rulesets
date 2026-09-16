rule TTP_XOR_MULT_DOSStub_8890 {
  strings:
    $key_8890 = { dc f8 [2] a8 e0 [2] ef e2 [2] a8 f3 [2] e6 ff [2] ea f5 [2] fd fe [2] e6 b0 [2] db }

  condition:
    any of them
}