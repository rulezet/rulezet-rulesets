rule TTP_XOR_MULT_DOSStub_500c {
  strings:
    $key_500c = { 04 64 [2] 70 7c [2] 37 7e [2] 70 6f [2] 3e 63 [2] 32 69 [2] 25 62 [2] 3e 2c [2] 03 }

  condition:
    any of them
}