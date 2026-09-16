rule TTP_XOR_MULT_DOSStub_7a6a {
  strings:
    $key_7a6a = { 2e 02 [2] 5a 1a [2] 1d 18 [2] 5a 09 [2] 14 05 [2] 18 0f [2] 0f 04 [2] 14 4a [2] 29 }

  condition:
    any of them
}