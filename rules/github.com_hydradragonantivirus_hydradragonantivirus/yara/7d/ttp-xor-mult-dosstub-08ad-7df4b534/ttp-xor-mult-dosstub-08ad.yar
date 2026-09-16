rule TTP_XOR_MULT_DOSStub_08ad {
  strings:
    $key_08ad = { 5c c5 [2] 28 dd [2] 6f df [2] 28 ce [2] 66 c2 [2] 6a c8 [2] 7d c3 [2] 66 8d [2] 5b }

  condition:
    any of them
}