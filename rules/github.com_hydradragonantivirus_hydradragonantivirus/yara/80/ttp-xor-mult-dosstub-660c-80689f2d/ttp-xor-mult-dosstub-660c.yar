rule TTP_XOR_MULT_DOSStub_660c {
  strings:
    $key_660c = { 32 64 [2] 46 7c [2] 01 7e [2] 46 6f [2] 08 63 [2] 04 69 [2] 13 62 [2] 08 2c [2] 35 }

  condition:
    any of them
}