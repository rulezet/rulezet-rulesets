rule TTP_XOR_MULT_DOSStub_7a0c {
  strings:
    $key_7a0c = { 2e 64 [2] 5a 7c [2] 1d 7e [2] 5a 6f [2] 14 63 [2] 18 69 [2] 0f 62 [2] 14 2c [2] 29 }

  condition:
    any of them
}