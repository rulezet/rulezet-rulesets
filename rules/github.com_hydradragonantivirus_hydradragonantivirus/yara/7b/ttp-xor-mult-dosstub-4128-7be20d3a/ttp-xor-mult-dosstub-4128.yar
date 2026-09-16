rule TTP_XOR_MULT_DOSStub_4128 {
  strings:
    $key_4128 = { 15 40 [2] 61 58 [2] 26 5a [2] 61 4b [2] 2f 47 [2] 23 4d [2] 34 46 [2] 2f 08 [2] 12 }

  condition:
    any of them
}