rule TTP_XOR_MULT_DOSStub_7ef5 {
  strings:
    $key_7ef5 = { 2a 9d [2] 5e 85 [2] 19 87 [2] 5e 96 [2] 10 9a [2] 1c 90 [2] 0b 9b [2] 10 d5 [2] 2d }

  condition:
    any of them
}