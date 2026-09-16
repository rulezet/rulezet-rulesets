rule TTP_XOR_MULT_DOSStub_661a {
  strings:
    $key_661a = { 32 72 [2] 46 6a [2] 01 68 [2] 46 79 [2] 08 75 [2] 04 7f [2] 13 74 [2] 08 3a [2] 35 }

  condition:
    any of them
}