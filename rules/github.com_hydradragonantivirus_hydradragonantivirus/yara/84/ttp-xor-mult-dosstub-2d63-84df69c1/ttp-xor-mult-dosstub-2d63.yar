rule TTP_XOR_MULT_DOSStub_2d63 {
  strings:
    $key_2d63 = { 79 0b [2] 0d 13 [2] 4a 11 [2] 0d 00 [2] 43 0c [2] 4f 06 [2] 58 0d [2] 43 43 [2] 7e }

  condition:
    any of them
}