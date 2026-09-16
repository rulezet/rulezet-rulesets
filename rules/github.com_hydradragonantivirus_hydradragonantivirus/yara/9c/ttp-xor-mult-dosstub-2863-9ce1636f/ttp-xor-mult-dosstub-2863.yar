rule TTP_XOR_MULT_DOSStub_2863 {
  strings:
    $key_2863 = { 7c 0b [2] 08 13 [2] 4f 11 [2] 08 00 [2] 46 0c [2] 4a 06 [2] 5d 0d [2] 46 43 [2] 7b }

  condition:
    any of them
}