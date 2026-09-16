rule TTP_XOR_MULT_DOSStub_3c65 {
  strings:
    $key_3c65 = { 68 0d [2] 1c 15 [2] 5b 17 [2] 1c 06 [2] 52 0a [2] 5e 00 [2] 49 0b [2] 52 45 [2] 6f }

  condition:
    any of them
}