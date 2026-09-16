rule TTP_XOR_MULT_DOSStub_5b28 {
  strings:
    $key_5b28 = { 0f 40 [2] 7b 58 [2] 3c 5a [2] 7b 4b [2] 35 47 [2] 39 4d [2] 2e 46 [2] 35 08 [2] 08 }

  condition:
    any of them
}