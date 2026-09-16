rule TTP_XOR_MULT_DOSStub_6268 {
  strings:
    $key_6268 = { 36 00 [2] 42 18 [2] 05 1a [2] 42 0b [2] 0c 07 [2] 00 0d [2] 17 06 [2] 0c 48 [2] 31 }

  condition:
    any of them
}