rule TTP_XOR_MULT_DOSStub_2c69 {
  strings:
    $key_2c69 = { 78 01 [2] 0c 19 [2] 4b 1b [2] 0c 0a [2] 42 06 [2] 4e 0c [2] 59 07 [2] 42 49 [2] 7f }

  condition:
    any of them
}