rule TTP_XOR_MULT_DOSStub_2c14 {
  strings:
    $key_2c14 = { 78 7c [2] 0c 64 [2] 4b 66 [2] 0c 77 [2] 42 7b [2] 4e 71 [2] 59 7a [2] 42 34 [2] 7f }

  condition:
    any of them
}