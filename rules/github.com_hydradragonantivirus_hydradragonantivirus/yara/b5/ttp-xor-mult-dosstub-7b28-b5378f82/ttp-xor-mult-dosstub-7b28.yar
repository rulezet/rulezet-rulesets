rule TTP_XOR_MULT_DOSStub_7b28 {
  strings:
    $key_7b28 = { 2f 40 [2] 5b 58 [2] 1c 5a [2] 5b 4b [2] 15 47 [2] 19 4d [2] 0e 46 [2] 15 08 [2] 28 }

  condition:
    any of them
}