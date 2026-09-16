rule TTP_XOR_MULT_DOSStub_666a {
  strings:
    $key_666a = { 32 02 [2] 46 1a [2] 01 18 [2] 46 09 [2] 08 05 [2] 04 0f [2] 13 04 [2] 08 4a [2] 35 }

  condition:
    any of them
}