rule TTP_XOR_MULT_DOSStub_7f16 {
  strings:
    $key_7f16 = { 2b 7e [2] 5f 66 [2] 18 64 [2] 5f 75 [2] 11 79 [2] 1d 73 [2] 0a 78 [2] 11 36 [2] 2c }

  condition:
    any of them
}