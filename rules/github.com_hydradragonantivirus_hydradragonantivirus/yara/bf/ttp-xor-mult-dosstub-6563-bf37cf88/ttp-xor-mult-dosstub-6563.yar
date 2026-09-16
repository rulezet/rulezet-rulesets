rule TTP_XOR_MULT_DOSStub_6563 {
  strings:
    $key_6563 = { 31 0b [2] 45 13 [2] 02 11 [2] 45 00 [2] 0b 0c [2] 07 06 [2] 10 0d [2] 0b 43 [2] 36 }

  condition:
    any of them
}