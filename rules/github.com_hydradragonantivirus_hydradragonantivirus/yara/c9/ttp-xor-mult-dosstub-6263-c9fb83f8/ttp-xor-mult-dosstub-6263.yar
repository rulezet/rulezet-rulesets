rule TTP_XOR_MULT_DOSStub_6263 {
  strings:
    $key_6263 = { 36 0b [2] 42 13 [2] 05 11 [2] 42 00 [2] 0c 0c [2] 00 06 [2] 17 0d [2] 0c 43 [2] 31 }

  condition:
    any of them
}