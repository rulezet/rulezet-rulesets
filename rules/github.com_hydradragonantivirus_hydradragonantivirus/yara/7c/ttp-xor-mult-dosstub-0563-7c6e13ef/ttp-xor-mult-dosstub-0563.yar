rule TTP_XOR_MULT_DOSStub_0563 {
  strings:
    $key_0563 = { 51 0b [2] 25 13 [2] 62 11 [2] 25 00 [2] 6b 0c [2] 67 06 [2] 70 0d [2] 6b 43 [2] 56 }

  condition:
    any of them
}