rule TTP_XOR_MULT_DOSStub_5e28 {
  strings:
    $key_5e28 = { 0a 40 [2] 7e 58 [2] 39 5a [2] 7e 4b [2] 30 47 [2] 3c 4d [2] 2b 46 [2] 30 08 [2] 0d }

  condition:
    any of them
}