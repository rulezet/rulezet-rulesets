rule TTP_XOR_MULT_DOSStub_574a {
  strings:
    $key_574a = { 03 22 [2] 77 3a [2] 30 38 [2] 77 29 [2] 39 25 [2] 35 2f [2] 22 24 [2] 39 6a [2] 04 }

  condition:
    any of them
}