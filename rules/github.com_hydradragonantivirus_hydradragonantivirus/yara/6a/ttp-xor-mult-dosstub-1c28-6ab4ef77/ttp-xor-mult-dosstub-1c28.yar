rule TTP_XOR_MULT_DOSStub_1c28 {
  strings:
    $key_1c28 = { 48 40 [2] 3c 58 [2] 7b 5a [2] 3c 4b [2] 72 47 [2] 7e 4d [2] 69 46 [2] 72 08 [2] 4f }

  condition:
    any of them
}