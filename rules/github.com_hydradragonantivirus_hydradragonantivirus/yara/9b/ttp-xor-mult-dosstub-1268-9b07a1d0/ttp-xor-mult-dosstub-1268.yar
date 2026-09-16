rule TTP_XOR_MULT_DOSStub_1268 {
  strings:
    $key_1268 = { 46 00 [2] 32 18 [2] 75 1a [2] 32 0b [2] 7c 07 [2] 70 0d [2] 67 06 [2] 7c 48 [2] 41 }

  condition:
    any of them
}