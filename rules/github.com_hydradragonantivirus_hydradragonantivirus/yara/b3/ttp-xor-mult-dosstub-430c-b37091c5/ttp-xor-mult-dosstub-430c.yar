rule TTP_XOR_MULT_DOSStub_430c {
  strings:
    $key_430c = { 17 64 [2] 63 7c [2] 24 7e [2] 63 6f [2] 2d 63 [2] 21 69 [2] 36 62 [2] 2d 2c [2] 10 }

  condition:
    any of them
}