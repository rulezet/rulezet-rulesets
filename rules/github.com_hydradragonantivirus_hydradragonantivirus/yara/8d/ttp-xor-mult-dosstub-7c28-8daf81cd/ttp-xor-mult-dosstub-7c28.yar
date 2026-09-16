rule TTP_XOR_MULT_DOSStub_7c28 {
  strings:
    $key_7c28 = { 28 40 [2] 5c 58 [2] 1b 5a [2] 5c 4b [2] 12 47 [2] 1e 4d [2] 09 46 [2] 12 08 [2] 2f }

  condition:
    any of them
}