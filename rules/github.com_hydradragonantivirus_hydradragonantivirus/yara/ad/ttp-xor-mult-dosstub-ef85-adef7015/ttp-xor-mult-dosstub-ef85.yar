rule TTP_XOR_MULT_DOSStub_ef85 {
  strings:
    $key_ef85 = { bb ed [2] cf f5 [2] 88 f7 [2] cf e6 [2] 81 ea [2] 8d e0 [2] 9a eb [2] 81 a5 [2] bc }

  condition:
    any of them
}