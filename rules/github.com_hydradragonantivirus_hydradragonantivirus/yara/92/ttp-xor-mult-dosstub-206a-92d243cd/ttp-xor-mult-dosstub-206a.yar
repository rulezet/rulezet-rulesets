rule TTP_XOR_MULT_DOSStub_206a {
  strings:
    $key_206a = { 74 02 [2] 00 1a [2] 47 18 [2] 00 09 [2] 4e 05 [2] 42 0f [2] 55 04 [2] 4e 4a [2] 73 }

  condition:
    any of them
}