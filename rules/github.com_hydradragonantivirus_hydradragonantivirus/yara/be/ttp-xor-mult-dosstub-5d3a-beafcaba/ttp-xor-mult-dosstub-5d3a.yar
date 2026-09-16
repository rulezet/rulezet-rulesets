rule TTP_XOR_MULT_DOSStub_5d3a {
  strings:
    $key_5d3a = { 09 52 [2] 7d 4a [2] 3a 48 [2] 7d 59 [2] 33 55 [2] 3f 5f [2] 28 54 [2] 33 1a [2] 0e }

  condition:
    any of them
}