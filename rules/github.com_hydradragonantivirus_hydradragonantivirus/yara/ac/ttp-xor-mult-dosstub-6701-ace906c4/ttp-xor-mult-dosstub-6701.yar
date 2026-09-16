rule TTP_XOR_MULT_DOSStub_6701 {
  strings:
    $key_6701 = { 33 69 [2] 47 71 [2] 00 73 [2] 47 62 [2] 09 6e [2] 05 64 [2] 12 6f [2] 09 21 [2] 34 }

  condition:
    any of them
}