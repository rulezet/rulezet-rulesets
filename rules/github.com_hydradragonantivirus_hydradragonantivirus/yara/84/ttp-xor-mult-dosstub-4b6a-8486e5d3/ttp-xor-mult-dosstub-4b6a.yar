rule TTP_XOR_MULT_DOSStub_4b6a {
  strings:
    $key_4b6a = { 1f 02 [2] 6b 1a [2] 2c 18 [2] 6b 09 [2] 25 05 [2] 29 0f [2] 3e 04 [2] 25 4a [2] 18 }

  condition:
    any of them
}