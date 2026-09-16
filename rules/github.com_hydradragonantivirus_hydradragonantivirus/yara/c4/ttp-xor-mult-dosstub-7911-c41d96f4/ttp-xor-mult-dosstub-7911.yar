rule TTP_XOR_MULT_DOSStub_7911 {
  strings:
    $key_7911 = { 2d 79 [2] 59 61 [2] 1e 63 [2] 59 72 [2] 17 7e [2] 1b 74 [2] 0c 7f [2] 17 31 [2] 2a }

  condition:
    any of them
}