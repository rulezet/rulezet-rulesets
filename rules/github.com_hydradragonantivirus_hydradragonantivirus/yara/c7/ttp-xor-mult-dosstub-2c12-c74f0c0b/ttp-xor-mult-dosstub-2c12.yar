rule TTP_XOR_MULT_DOSStub_2c12 {
  strings:
    $key_2c12 = { 78 7a [2] 0c 62 [2] 4b 60 [2] 0c 71 [2] 42 7d [2] 4e 77 [2] 59 7c [2] 42 32 [2] 7f }

  condition:
    any of them
}