rule TTP_XOR_MULT_DOSStub_3c48 {
  strings:
    $key_3c48 = { 68 20 [2] 1c 38 [2] 5b 3a [2] 1c 2b [2] 52 27 [2] 5e 2d [2] 49 26 [2] 52 68 [2] 6f }

  condition:
    any of them
}