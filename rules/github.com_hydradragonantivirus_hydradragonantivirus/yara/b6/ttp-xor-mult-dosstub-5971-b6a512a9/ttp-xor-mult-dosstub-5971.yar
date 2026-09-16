rule TTP_XOR_MULT_DOSStub_5971 {
  strings:
    $key_5971 = { 0d 19 [2] 79 01 [2] 3e 03 [2] 79 12 [2] 37 1e [2] 3b 14 [2] 2c 1f [2] 37 51 [2] 0a }

  condition:
    any of them
}