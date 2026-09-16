rule TTP_XOR_MULT_DOSStub_423c {
  strings:
    $key_423c = { 16 54 [2] 62 4c [2] 25 4e [2] 62 5f [2] 2c 53 [2] 20 59 [2] 37 52 [2] 2c 1c [2] 11 }

  condition:
    any of them
}