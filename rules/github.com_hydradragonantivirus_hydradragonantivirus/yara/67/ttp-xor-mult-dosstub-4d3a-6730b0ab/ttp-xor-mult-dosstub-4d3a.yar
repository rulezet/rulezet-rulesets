rule TTP_XOR_MULT_DOSStub_4d3a {
  strings:
    $key_4d3a = { 19 52 [2] 6d 4a [2] 2a 48 [2] 6d 59 [2] 23 55 [2] 2f 5f [2] 38 54 [2] 23 1a [2] 1e }

  condition:
    any of them
}