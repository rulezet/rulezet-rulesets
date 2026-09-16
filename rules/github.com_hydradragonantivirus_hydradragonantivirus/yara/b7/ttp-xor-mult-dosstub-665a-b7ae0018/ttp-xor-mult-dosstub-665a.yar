rule TTP_XOR_MULT_DOSStub_665a {
  strings:
    $key_665a = { 32 32 [2] 46 2a [2] 01 28 [2] 46 39 [2] 08 35 [2] 04 3f [2] 13 34 [2] 08 7a [2] 35 }

  condition:
    any of them
}