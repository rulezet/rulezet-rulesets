rule TTP_XOR_MULT_DOSStub_3a0c {
  strings:
    $key_3a0c = { 6e 64 [2] 1a 7c [2] 5d 7e [2] 1a 6f [2] 54 63 [2] 58 69 [2] 4f 62 [2] 54 2c [2] 69 }

  condition:
    any of them
}