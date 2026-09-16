rule TTP_XOR_MULT_DOSStub_0b63 {
  strings:
    $key_0b63 = { 5f 0b [2] 2b 13 [2] 6c 11 [2] 2b 00 [2] 65 0c [2] 69 06 [2] 7e 0d [2] 65 43 [2] 58 }

  condition:
    any of them
}