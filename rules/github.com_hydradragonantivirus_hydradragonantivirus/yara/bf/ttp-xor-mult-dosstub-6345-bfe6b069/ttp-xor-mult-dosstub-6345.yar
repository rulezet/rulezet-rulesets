rule TTP_XOR_MULT_DOSStub_6345 {
  strings:
    $key_6345 = { 37 2d [2] 43 35 [2] 04 37 [2] 43 26 [2] 0d 2a [2] 01 20 [2] 16 2b [2] 0d 65 [2] 30 }

  condition:
    any of them
}