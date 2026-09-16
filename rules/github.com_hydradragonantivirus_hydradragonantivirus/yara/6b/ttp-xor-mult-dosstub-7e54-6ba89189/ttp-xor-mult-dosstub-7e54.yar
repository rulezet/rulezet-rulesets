rule TTP_XOR_MULT_DOSStub_7e54 {
  strings:
    $key_7e54 = { 2a 3c [2] 5e 24 [2] 19 26 [2] 5e 37 [2] 10 3b [2] 1c 31 [2] 0b 3a [2] 10 74 [2] 2d }

  condition:
    any of them
}