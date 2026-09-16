rule TTP_XOR_MULT_DOSStub_2079 {
  strings:
    $key_2079 = { 74 11 [2] 00 09 [2] 47 0b [2] 00 1a [2] 4e 16 [2] 42 1c [2] 55 17 [2] 4e 59 [2] 73 }

  condition:
    any of them
}