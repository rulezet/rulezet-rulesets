rule TTP_XOR_MULT_DOSStub_5e49 {
  strings:
    $key_5e49 = { 0a 21 [2] 7e 39 [2] 39 3b [2] 7e 2a [2] 30 26 [2] 3c 2c [2] 2b 27 [2] 30 69 [2] 0d }

  condition:
    any of them
}