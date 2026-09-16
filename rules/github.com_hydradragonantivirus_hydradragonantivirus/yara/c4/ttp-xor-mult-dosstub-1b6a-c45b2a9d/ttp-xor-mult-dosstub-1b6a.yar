rule TTP_XOR_MULT_DOSStub_1b6a {
  strings:
    $key_1b6a = { 4f 02 [2] 3b 1a [2] 7c 18 [2] 3b 09 [2] 75 05 [2] 79 0f [2] 6e 04 [2] 75 4a [2] 48 }

  condition:
    any of them
}