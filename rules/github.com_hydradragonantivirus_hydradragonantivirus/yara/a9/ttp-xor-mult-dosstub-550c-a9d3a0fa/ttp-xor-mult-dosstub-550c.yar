rule TTP_XOR_MULT_DOSStub_550c {
  strings:
    $key_550c = { 01 64 [2] 75 7c [2] 32 7e [2] 75 6f [2] 3b 63 [2] 37 69 [2] 20 62 [2] 3b 2c [2] 06 }

  condition:
    any of them
}