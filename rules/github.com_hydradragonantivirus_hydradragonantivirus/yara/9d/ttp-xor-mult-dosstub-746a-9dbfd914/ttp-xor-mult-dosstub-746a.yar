rule TTP_XOR_MULT_DOSStub_746a {
  strings:
    $key_746a = { 20 02 [2] 54 1a [2] 13 18 [2] 54 09 [2] 1a 05 [2] 16 0f [2] 01 04 [2] 1a 4a [2] 27 }

  condition:
    any of them
}