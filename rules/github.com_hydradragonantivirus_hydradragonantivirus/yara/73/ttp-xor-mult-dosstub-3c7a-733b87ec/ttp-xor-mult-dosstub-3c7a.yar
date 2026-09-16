rule TTP_XOR_MULT_DOSStub_3c7a {
  strings:
    $key_3c7a = { 68 12 [2] 1c 0a [2] 5b 08 [2] 1c 19 [2] 52 15 [2] 5e 1f [2] 49 14 [2] 52 5a [2] 6f }

  condition:
    any of them
}