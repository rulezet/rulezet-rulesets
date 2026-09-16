rule TTP_XOR_MULT_DOSStub_660a {
  strings:
    $key_660a = { 32 62 [2] 46 7a [2] 01 78 [2] 46 69 [2] 08 65 [2] 04 6f [2] 13 64 [2] 08 2a [2] 35 }

  condition:
    any of them
}