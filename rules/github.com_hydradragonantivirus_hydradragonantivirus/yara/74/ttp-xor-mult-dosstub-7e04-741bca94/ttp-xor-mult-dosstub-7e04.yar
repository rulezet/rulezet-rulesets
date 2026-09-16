rule TTP_XOR_MULT_DOSStub_7e04 {
  strings:
    $key_7e04 = { 2a 6c [2] 5e 74 [2] 19 76 [2] 5e 67 [2] 10 6b [2] 1c 61 [2] 0b 6a [2] 10 24 [2] 2d }

  condition:
    any of them
}