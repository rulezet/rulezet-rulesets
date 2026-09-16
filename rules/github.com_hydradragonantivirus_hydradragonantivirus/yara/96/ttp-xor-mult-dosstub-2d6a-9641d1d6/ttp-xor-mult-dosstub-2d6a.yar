rule TTP_XOR_MULT_DOSStub_2d6a {
  strings:
    $key_2d6a = { 79 02 [2] 0d 1a [2] 4a 18 [2] 0d 09 [2] 43 05 [2] 4f 0f [2] 58 04 [2] 43 4a [2] 7e }

  condition:
    any of them
}