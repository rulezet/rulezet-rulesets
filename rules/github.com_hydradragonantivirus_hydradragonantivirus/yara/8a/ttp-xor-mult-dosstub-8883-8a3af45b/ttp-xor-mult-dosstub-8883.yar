rule TTP_XOR_MULT_DOSStub_8883 {
  strings:
    $key_8883 = { dc eb [2] a8 f3 [2] ef f1 [2] a8 e0 [2] e6 ec [2] ea e6 [2] fd ed [2] e6 a3 [2] db }

  condition:
    any of them
}