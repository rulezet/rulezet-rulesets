rule TTP_XOR_MULT_DOSStub_3979 {
  strings:
    $key_3979 = { 6d 11 [2] 19 09 [2] 5e 0b [2] 19 1a [2] 57 16 [2] 5b 1c [2] 4c 17 [2] 57 59 [2] 6a }

  condition:
    any of them
}