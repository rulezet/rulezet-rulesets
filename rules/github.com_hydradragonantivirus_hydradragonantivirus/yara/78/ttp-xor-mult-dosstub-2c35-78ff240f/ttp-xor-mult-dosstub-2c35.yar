rule TTP_XOR_MULT_DOSStub_2c35 {
  strings:
    $key_2c35 = { 78 5d [2] 0c 45 [2] 4b 47 [2] 0c 56 [2] 42 5a [2] 4e 50 [2] 59 5b [2] 42 15 [2] 7f }

  condition:
    any of them
}