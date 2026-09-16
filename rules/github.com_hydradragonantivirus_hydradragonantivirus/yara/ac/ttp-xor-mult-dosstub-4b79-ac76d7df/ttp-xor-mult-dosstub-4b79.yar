rule TTP_XOR_MULT_DOSStub_4b79 {
  strings:
    $key_4b79 = { 1f 11 [2] 6b 09 [2] 2c 0b [2] 6b 1a [2] 25 16 [2] 29 1c [2] 3e 17 [2] 25 59 [2] 18 }

  condition:
    any of them
}