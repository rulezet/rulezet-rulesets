rule TTP_XOR_MULT_DOSStub_48ad {
  strings:
    $key_48ad = { 1c c5 [2] 68 dd [2] 2f df [2] 68 ce [2] 26 c2 [2] 2a c8 [2] 3d c3 [2] 26 8d [2] 1b }

  condition:
    any of them
}