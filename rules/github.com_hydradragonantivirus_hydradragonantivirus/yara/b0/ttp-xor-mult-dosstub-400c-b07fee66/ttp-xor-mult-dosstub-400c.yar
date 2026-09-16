rule TTP_XOR_MULT_DOSStub_400c {
  strings:
    $key_400c = { 14 64 [2] 60 7c [2] 27 7e [2] 60 6f [2] 2e 63 [2] 22 69 [2] 35 62 [2] 2e 2c [2] 13 }

  condition:
    any of them
}