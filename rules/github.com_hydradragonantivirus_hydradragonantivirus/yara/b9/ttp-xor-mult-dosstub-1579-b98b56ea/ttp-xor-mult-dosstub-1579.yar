rule TTP_XOR_MULT_DOSStub_1579 {
  strings:
    $key_1579 = { 41 11 [2] 35 09 [2] 72 0b [2] 35 1a [2] 7b 16 [2] 77 1c [2] 60 17 [2] 7b 59 [2] 46 }

  condition:
    any of them
}