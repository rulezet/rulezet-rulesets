rule TTP_XOR_MULT_DOSStub_88de {
  strings:
    $key_88de = { dc b6 [2] a8 ae [2] ef ac [2] a8 bd [2] e6 b1 [2] ea bb [2] fd b0 [2] e6 fe [2] db }

  condition:
    any of them
}