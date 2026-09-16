rule TTP_XOR_MULT_DOSStub_7e15 {
  strings:
    $key_7e15 = { 2a 7d [2] 5e 65 [2] 19 67 [2] 5e 76 [2] 10 7a [2] 1c 70 [2] 0b 7b [2] 10 35 [2] 2d }

  condition:
    any of them
}