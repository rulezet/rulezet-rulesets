rule TTP_XOR_MULT_DOSStub_070c {
  strings:
    $key_070c = { 53 64 [2] 27 7c [2] 60 7e [2] 27 6f [2] 69 63 [2] 65 69 [2] 72 62 [2] 69 2c [2] 54 }

  condition:
    any of them
}