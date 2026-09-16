rule TTP_XOR_MULT_DOSStub_560c {
  strings:
    $key_560c = { 02 64 [2] 76 7c [2] 31 7e [2] 76 6f [2] 38 63 [2] 34 69 [2] 23 62 [2] 38 2c [2] 05 }

  condition:
    any of them
}