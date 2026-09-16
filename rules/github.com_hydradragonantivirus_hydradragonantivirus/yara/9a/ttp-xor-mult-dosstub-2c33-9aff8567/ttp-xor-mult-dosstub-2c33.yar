rule TTP_XOR_MULT_DOSStub_2c33 {
  strings:
    $key_2c33 = { 78 5b [2] 0c 43 [2] 4b 41 [2] 0c 50 [2] 42 5c [2] 4e 56 [2] 59 5d [2] 42 13 [2] 7f }

  condition:
    any of them
}