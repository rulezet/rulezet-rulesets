rule TTP_XOR_MULT_DOSStub_c9de {
  strings:
    $key_c9de = { 9d b6 [2] e9 ae [2] ae ac [2] e9 bd [2] a7 b1 [2] ab bb [2] bc b0 [2] a7 fe [2] 9a }

  condition:
    any of them
}