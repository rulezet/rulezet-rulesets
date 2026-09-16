rule TTP_XOR_MULT_DOSStub_1b25 {
  strings:
    $key_1b25 = { 4f 4d [2] 3b 55 [2] 7c 57 [2] 3b 46 [2] 75 4a [2] 79 40 [2] 6e 4b [2] 75 05 [2] 48 }

  condition:
    any of them
}