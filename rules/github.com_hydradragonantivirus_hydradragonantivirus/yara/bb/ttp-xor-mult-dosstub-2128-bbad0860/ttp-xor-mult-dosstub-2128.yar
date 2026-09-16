rule TTP_XOR_MULT_DOSStub_2128 {
  strings:
    $key_2128 = { 75 40 [2] 01 58 [2] 46 5a [2] 01 4b [2] 4f 47 [2] 43 4d [2] 54 46 [2] 4f 08 [2] 72 }

  condition:
    any of them
}