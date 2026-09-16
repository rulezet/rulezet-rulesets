rule TTP_XOR_MULT_DOSStub_3e49 {
  strings:
    $key_3e49 = { 6a 21 [2] 1e 39 [2] 59 3b [2] 1e 2a [2] 50 26 [2] 5c 2c [2] 4b 27 [2] 50 69 [2] 6d }

  condition:
    any of them
}