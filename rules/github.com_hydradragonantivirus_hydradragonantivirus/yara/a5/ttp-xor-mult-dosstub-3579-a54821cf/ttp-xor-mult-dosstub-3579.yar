rule TTP_XOR_MULT_DOSStub_3579 {
  strings:
    $key_3579 = { 61 11 [2] 15 09 [2] 52 0b [2] 15 1a [2] 5b 16 [2] 57 1c [2] 40 17 [2] 5b 59 [2] 66 }

  condition:
    any of them
}