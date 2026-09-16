rule TTP_XOR_MULT_DOSStub_c8ad {
  strings:
    $key_c8ad = { 9c c5 [2] e8 dd [2] af df [2] e8 ce [2] a6 c2 [2] aa c8 [2] bd c3 [2] a6 8d [2] 9b }

  condition:
    any of them
}