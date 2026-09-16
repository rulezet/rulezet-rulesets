rule TTP_XOR_MULT_DOSStub_4a61 {
  strings:
    $key_4a61 = { 1e 09 [2] 6a 11 [2] 2d 13 [2] 6a 02 [2] 24 0e [2] 28 04 [2] 3f 0f [2] 24 41 [2] 19 }

  condition:
    any of them
}