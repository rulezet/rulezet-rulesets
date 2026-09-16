rule TTP_XOR_MULT_DOSStub_170c {
  strings:
    $key_170c = { 43 64 [2] 37 7c [2] 70 7e [2] 37 6f [2] 79 63 [2] 75 69 [2] 62 62 [2] 79 2c [2] 44 }

  condition:
    any of them
}