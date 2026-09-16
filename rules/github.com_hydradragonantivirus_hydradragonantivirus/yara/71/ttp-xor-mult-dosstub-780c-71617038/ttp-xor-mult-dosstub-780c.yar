rule TTP_XOR_MULT_DOSStub_780c {
  strings:
    $key_780c = { 2c 64 [2] 58 7c [2] 1f 7e [2] 58 6f [2] 16 63 [2] 1a 69 [2] 0d 62 [2] 16 2c [2] 2b }

  condition:
    any of them
}