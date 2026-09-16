rule TTP_XOR_MULT_DOSStub_6c09 {
  strings:
    $key_6c09 = { 38 61 [2] 4c 79 [2] 0b 7b [2] 4c 6a [2] 02 66 [2] 0e 6c [2] 19 67 [2] 02 29 [2] 3f }

  condition:
    any of them
}