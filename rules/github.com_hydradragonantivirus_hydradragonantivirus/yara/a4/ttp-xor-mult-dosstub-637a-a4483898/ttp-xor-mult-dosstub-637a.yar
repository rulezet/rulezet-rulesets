rule TTP_XOR_MULT_DOSStub_637a {
  strings:
    $key_637a = { 37 12 [2] 43 0a [2] 04 08 [2] 43 19 [2] 0d 15 [2] 01 1f [2] 16 14 [2] 0d 5a [2] 30 }

  condition:
    any of them
}