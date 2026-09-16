rule TTP_XOR_MULT_DOSStub_7179 {
  strings:
    $key_7179 = { 25 11 [2] 51 09 [2] 16 0b [2] 51 1a [2] 1f 16 [2] 13 1c [2] 04 17 [2] 1f 59 [2] 22 }

  condition:
    any of them
}