rule TTP_XOR_MULT_DOSStub_6c08 {
  strings:
    $key_6c08 = { 38 60 [2] 4c 78 [2] 0b 7a [2] 4c 6b [2] 02 67 [2] 0e 6d [2] 19 66 [2] 02 28 [2] 3f }

  condition:
    any of them
}