rule TTP_XOR_MULT_DOSStub_5c6a {
  strings:
    $key_5c6a = { 08 02 [2] 7c 1a [2] 3b 18 [2] 7c 09 [2] 32 05 [2] 3e 0f [2] 29 04 [2] 32 4a [2] 0f }

  condition:
    any of them
}