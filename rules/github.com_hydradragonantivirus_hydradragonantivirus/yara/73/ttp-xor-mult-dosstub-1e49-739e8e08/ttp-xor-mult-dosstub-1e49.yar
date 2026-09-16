rule TTP_XOR_MULT_DOSStub_1e49 {
  strings:
    $key_1e49 = { 4a 21 [2] 3e 39 [2] 79 3b [2] 3e 2a [2] 70 26 [2] 7c 2c [2] 6b 27 [2] 70 69 [2] 4d }

  condition:
    any of them
}