rule TTP_XOR_MULT_DOSStub_626a {
  strings:
    $key_626a = { 36 02 [2] 42 1a [2] 05 18 [2] 42 09 [2] 0c 05 [2] 00 0f [2] 17 04 [2] 0c 4a [2] 31 }

  condition:
    any of them
}