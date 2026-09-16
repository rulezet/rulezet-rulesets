rule TTP_XOR_MULT_DOSStub_664a {
  strings:
    $key_664a = { 32 22 [2] 46 3a [2] 01 38 [2] 46 29 [2] 08 25 [2] 04 2f [2] 13 24 [2] 08 6a [2] 35 }

  condition:
    any of them
}