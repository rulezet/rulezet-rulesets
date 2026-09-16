rule TTP_XOR_MULT_DOSStub_750c {
  strings:
    $key_750c = { 21 64 [2] 55 7c [2] 12 7e [2] 55 6f [2] 1b 63 [2] 17 69 [2] 00 62 [2] 1b 2c [2] 26 }

  condition:
    any of them
}