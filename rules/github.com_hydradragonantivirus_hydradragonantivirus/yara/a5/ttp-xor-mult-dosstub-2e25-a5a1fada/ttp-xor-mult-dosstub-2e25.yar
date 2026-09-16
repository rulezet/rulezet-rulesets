rule TTP_XOR_MULT_DOSStub_2e25 {
  strings:
    $key_2e25 = { 7a 4d [2] 0e 55 [2] 49 57 [2] 0e 46 [2] 40 4a [2] 4c 40 [2] 5b 4b [2] 40 05 [2] 7d }

  condition:
    any of them
}