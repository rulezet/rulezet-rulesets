rule TTP_XOR_MULT_DOSStub_3c78 {
  strings:
    $key_3c78 = { 68 10 [2] 1c 08 [2] 5b 0a [2] 1c 1b [2] 52 17 [2] 5e 1d [2] 49 16 [2] 52 58 [2] 6f }

  condition:
    any of them
}