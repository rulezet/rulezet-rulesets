rule TTP_XOR_MULT_DOSStub_285a {
  strings:
    $key_285a = { 7c 32 [2] 08 2a [2] 4f 28 [2] 08 39 [2] 46 35 [2] 4a 3f [2] 5d 34 [2] 46 7a [2] 7b }

  condition:
    any of them
}