rule TTP_XOR_MULT_DOSStub_5215 {
  strings:
    $key_5215 = { 06 7d [2] 72 65 [2] 35 67 [2] 72 76 [2] 3c 7a [2] 30 70 [2] 27 7b [2] 3c 35 [2] 01 }

  condition:
    any of them
}