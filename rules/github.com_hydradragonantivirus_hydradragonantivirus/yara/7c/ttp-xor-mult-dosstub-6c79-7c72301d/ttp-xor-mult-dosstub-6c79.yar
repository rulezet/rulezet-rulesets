rule TTP_XOR_MULT_DOSStub_6c79 {
  strings:
    $key_6c79 = { 38 11 [2] 4c 09 [2] 0b 0b [2] 4c 1a [2] 02 16 [2] 0e 1c [2] 19 17 [2] 02 59 [2] 3f }

  condition:
    any of them
}