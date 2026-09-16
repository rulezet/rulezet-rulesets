rule TTP_XOR_MULT_DOSStub_4376 {
  strings:
    $key_4376 = { 17 1e [2] 63 06 [2] 24 04 [2] 63 15 [2] 2d 19 [2] 21 13 [2] 36 18 [2] 2d 56 [2] 10 }

  condition:
    any of them
}