rule TTP_XOR_MULT_DOSStub_5e25 {
  strings:
    $key_5e25 = { 0a 4d [2] 7e 55 [2] 39 57 [2] 7e 46 [2] 30 4a [2] 3c 40 [2] 2b 4b [2] 30 05 [2] 0d }

  condition:
    any of them
}