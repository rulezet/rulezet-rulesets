rule TTP_XOR_MULT_DOSStub_0caf {
  strings:
    $key_0caf = { 58 c7 [2] 2c df [2] 6b dd [2] 2c cc [2] 62 c0 [2] 6e ca [2] 79 c1 [2] 62 8f [2] 5f }

  condition:
    any of them
}