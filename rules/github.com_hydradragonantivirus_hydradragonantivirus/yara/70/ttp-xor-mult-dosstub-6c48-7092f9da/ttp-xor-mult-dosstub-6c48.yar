rule TTP_XOR_MULT_DOSStub_6c48 {
  strings:
    $key_6c48 = { 38 20 [2] 4c 38 [2] 0b 3a [2] 4c 2b [2] 02 27 [2] 0e 2d [2] 19 26 [2] 02 68 [2] 3f }

  condition:
    any of them
}