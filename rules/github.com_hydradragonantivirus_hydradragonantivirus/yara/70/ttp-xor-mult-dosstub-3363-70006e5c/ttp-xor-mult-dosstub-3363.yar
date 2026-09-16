rule TTP_XOR_MULT_DOSStub_3363 {
  strings:
    $key_3363 = { 67 0b [2] 13 13 [2] 54 11 [2] 13 00 [2] 5d 0c [2] 51 06 [2] 46 0d [2] 5d 43 [2] 60 }

  condition:
    any of them
}