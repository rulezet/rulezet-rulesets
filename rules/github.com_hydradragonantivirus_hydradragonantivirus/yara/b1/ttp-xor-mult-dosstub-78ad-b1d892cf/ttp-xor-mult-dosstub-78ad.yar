rule TTP_XOR_MULT_DOSStub_78ad {
  strings:
    $key_78ad = { 2c c5 [2] 58 dd [2] 1f df [2] 58 ce [2] 16 c2 [2] 1a c8 [2] 0d c3 [2] 16 8d [2] 2b }

  condition:
    any of them
}