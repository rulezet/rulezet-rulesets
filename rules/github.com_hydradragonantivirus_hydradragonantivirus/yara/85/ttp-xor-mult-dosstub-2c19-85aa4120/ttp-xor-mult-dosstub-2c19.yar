rule TTP_XOR_MULT_DOSStub_2c19 {
  strings:
    $key_2c19 = { 78 71 [2] 0c 69 [2] 4b 6b [2] 0c 7a [2] 42 76 [2] 4e 7c [2] 59 77 [2] 42 39 [2] 7f }

  condition:
    any of them
}