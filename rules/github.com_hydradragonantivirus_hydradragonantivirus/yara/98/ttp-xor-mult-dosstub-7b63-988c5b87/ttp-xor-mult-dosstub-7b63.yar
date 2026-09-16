rule TTP_XOR_MULT_DOSStub_7b63 {
  strings:
    $key_7b63 = { 2f 0b [2] 5b 13 [2] 1c 11 [2] 5b 00 [2] 15 0c [2] 19 06 [2] 0e 0d [2] 15 43 [2] 28 }

  condition:
    any of them
}