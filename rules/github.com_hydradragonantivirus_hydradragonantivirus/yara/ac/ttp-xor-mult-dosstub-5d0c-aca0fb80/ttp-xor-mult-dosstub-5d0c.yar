rule TTP_XOR_MULT_DOSStub_5d0c {
  strings:
    $key_5d0c = { 09 64 [2] 7d 7c [2] 3a 7e [2] 7d 6f [2] 33 63 [2] 3f 69 [2] 28 62 [2] 33 2c [2] 0e }

  condition:
    any of them
}