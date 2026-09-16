rule TTP_XOR_MULT_DOSStub_667a {
  strings:
    $key_667a = { 32 12 [2] 46 0a [2] 01 08 [2] 46 19 [2] 08 15 [2] 04 1f [2] 13 14 [2] 08 5a [2] 35 }

  condition:
    any of them
}