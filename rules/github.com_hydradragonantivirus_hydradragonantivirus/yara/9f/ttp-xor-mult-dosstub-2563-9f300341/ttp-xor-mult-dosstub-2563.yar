rule TTP_XOR_MULT_DOSStub_2563 {
  strings:
    $key_2563 = { 71 0b [2] 05 13 [2] 42 11 [2] 05 00 [2] 4b 0c [2] 47 06 [2] 50 0d [2] 4b 43 [2] 76 }

  condition:
    any of them
}