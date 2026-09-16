rule TTP_XOR_MULT_DOSStub_710c {
  strings:
    $key_710c = { 25 64 [2] 51 7c [2] 16 7e [2] 51 6f [2] 1f 63 [2] 13 69 [2] 04 62 [2] 1f 2c [2] 22 }

  condition:
    any of them
}