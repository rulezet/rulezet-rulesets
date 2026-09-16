rule TTP_XOR_MULT_DOSStub_3b63 {
  strings:
    $key_3b63 = { 6f 0b [2] 1b 13 [2] 5c 11 [2] 1b 00 [2] 55 0c [2] 59 06 [2] 4e 0d [2] 55 43 [2] 68 }

  condition:
    any of them
}