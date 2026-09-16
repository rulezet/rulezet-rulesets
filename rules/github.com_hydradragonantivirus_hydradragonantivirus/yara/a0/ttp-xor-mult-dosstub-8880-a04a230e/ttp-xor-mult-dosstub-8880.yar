rule TTP_XOR_MULT_DOSStub_8880 {
  strings:
    $key_8880 = { dc e8 [2] a8 f0 [2] ef f2 [2] a8 e3 [2] e6 ef [2] ea e5 [2] fd ee [2] e6 a0 [2] db }

  condition:
    any of them
}