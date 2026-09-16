rule TTP_XOR_MULT_DOSStub_556a {
  strings:
    $key_556a = { 01 02 [2] 75 1a [2] 32 18 [2] 75 09 [2] 3b 05 [2] 37 0f [2] 20 04 [2] 3b 4a [2] 06 }

  condition:
    any of them
}