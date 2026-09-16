rule TTP_XOR_MULT_DOSStub_7f6a {
  strings:
    $key_7f6a = { 2b 02 [2] 5f 1a [2] 18 18 [2] 5f 09 [2] 11 05 [2] 1d 0f [2] 0a 04 [2] 11 4a [2] 2c }

  condition:
    any of them
}