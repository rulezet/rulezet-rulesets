rule TTP_XOR_MULT_DOSStub_2b63 {
  strings:
    $key_2b63 = { 7f 0b [2] 0b 13 [2] 4c 11 [2] 0b 00 [2] 45 0c [2] 49 06 [2] 5e 0d [2] 45 43 [2] 78 }

  condition:
    any of them
}