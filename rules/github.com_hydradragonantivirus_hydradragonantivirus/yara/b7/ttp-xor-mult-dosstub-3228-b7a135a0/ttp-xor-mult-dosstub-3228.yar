rule TTP_XOR_MULT_DOSStub_3228 {
  strings:
    $key_3228 = { 66 40 [2] 12 58 [2] 55 5a [2] 12 4b [2] 5c 47 [2] 50 4d [2] 47 46 [2] 5c 08 [2] 61 }

  condition:
    any of them
}