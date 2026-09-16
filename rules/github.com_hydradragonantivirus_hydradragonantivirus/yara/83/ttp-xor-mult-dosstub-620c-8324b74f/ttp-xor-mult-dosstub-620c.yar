rule TTP_XOR_MULT_DOSStub_620c {
  strings:
    $key_620c = { 36 64 [2] 42 7c [2] 05 7e [2] 42 6f [2] 0c 63 [2] 00 69 [2] 17 62 [2] 0c 2c [2] 31 }

  condition:
    any of them
}