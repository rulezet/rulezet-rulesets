rule TTP_XOR_MULT_DOSStub_c98d {
  strings:
    $key_c98d = { 9d e5 [2] e9 fd [2] ae ff [2] e9 ee [2] a7 e2 [2] ab e8 [2] bc e3 [2] a7 ad [2] 9a }

  condition:
    any of them
}