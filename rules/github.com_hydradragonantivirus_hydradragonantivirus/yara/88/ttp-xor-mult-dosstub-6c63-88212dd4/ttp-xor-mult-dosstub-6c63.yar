rule TTP_XOR_MULT_DOSStub_6c63 {
  strings:
    $key_6c63 = { 38 0b [2] 4c 13 [2] 0b 11 [2] 4c 00 [2] 02 0c [2] 0e 06 [2] 19 0d [2] 02 43 [2] 3f }

  condition:
    any of them
}