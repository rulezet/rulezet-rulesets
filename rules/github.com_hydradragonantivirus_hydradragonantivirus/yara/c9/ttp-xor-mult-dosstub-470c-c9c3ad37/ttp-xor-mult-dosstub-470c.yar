rule TTP_XOR_MULT_DOSStub_470c {
  strings:
    $key_470c = { 13 64 [2] 67 7c [2] 20 7e [2] 67 6f [2] 29 63 [2] 25 69 [2] 32 62 [2] 29 2c [2] 14 }

  condition:
    any of them
}