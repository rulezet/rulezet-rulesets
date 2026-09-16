rule TTP_XOR_MULT_DOSStub_6c69 {
  strings:
    $key_6c69 = { 38 01 [2] 4c 19 [2] 0b 1b [2] 4c 0a [2] 02 06 [2] 0e 0c [2] 19 07 [2] 02 49 [2] 3f }

  condition:
    any of them
}