rule TTP_XOR_MULT_DOSStub_2c64 {
  strings:
    $key_2c64 = { 78 0c [2] 0c 14 [2] 4b 16 [2] 0c 07 [2] 42 0b [2] 4e 01 [2] 59 0a [2] 42 44 [2] 7f }

  condition:
    any of them
}