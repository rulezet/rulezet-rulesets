rule TTP_XOR_MULT_DOSStub_2e49 {
  strings:
    $key_2e49 = { 7a 21 [2] 0e 39 [2] 49 3b [2] 0e 2a [2] 40 26 [2] 4c 2c [2] 5b 27 [2] 40 69 [2] 7d }

  condition:
    any of them
}