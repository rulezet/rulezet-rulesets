rule TTP_XOR_MULT_DOSStub_7c25 {
  strings:
    $key_7c25 = { 28 4d [2] 5c 55 [2] 1b 57 [2] 5c 46 [2] 12 4a [2] 1e 40 [2] 09 4b [2] 12 05 [2] 2f }

  condition:
    any of them
}