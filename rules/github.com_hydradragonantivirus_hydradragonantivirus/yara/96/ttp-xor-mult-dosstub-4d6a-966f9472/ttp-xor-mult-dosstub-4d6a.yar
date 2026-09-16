rule TTP_XOR_MULT_DOSStub_4d6a {
  strings:
    $key_4d6a = { 19 02 [2] 6d 1a [2] 2a 18 [2] 6d 09 [2] 23 05 [2] 2f 0f [2] 38 04 [2] 23 4a [2] 1e }

  condition:
    any of them
}