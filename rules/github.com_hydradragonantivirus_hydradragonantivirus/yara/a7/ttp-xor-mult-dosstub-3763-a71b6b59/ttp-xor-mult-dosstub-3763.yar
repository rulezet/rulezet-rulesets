rule TTP_XOR_MULT_DOSStub_3763 {
  strings:
    $key_3763 = { 63 0b [2] 17 13 [2] 50 11 [2] 17 00 [2] 59 0c [2] 55 06 [2] 42 0d [2] 59 43 [2] 64 }

  condition:
    any of them
}