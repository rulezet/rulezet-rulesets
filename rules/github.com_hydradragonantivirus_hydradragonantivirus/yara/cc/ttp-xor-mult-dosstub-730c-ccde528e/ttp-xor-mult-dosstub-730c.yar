rule TTP_XOR_MULT_DOSStub_730c {
  strings:
    $key_730c = { 27 64 [2] 53 7c [2] 14 7e [2] 53 6f [2] 1d 63 [2] 11 69 [2] 06 62 [2] 1d 2c [2] 20 }

  condition:
    any of them
}