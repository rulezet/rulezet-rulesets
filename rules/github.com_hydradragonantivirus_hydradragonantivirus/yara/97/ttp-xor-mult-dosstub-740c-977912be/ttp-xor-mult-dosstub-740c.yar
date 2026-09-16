rule TTP_XOR_MULT_DOSStub_740c {
  strings:
    $key_740c = { 20 64 [2] 54 7c [2] 13 7e [2] 54 6f [2] 1a 63 [2] 16 69 [2] 01 62 [2] 1a 2c [2] 27 }

  condition:
    any of them
}