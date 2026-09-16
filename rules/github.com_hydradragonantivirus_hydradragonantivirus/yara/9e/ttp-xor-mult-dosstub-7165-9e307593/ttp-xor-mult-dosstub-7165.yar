rule TTP_XOR_MULT_DOSStub_7165 {
  strings:
    $key_7165 = { 25 0d [2] 51 15 [2] 16 17 [2] 51 06 [2] 1f 0a [2] 13 00 [2] 04 0b [2] 1f 45 [2] 22 }

  condition:
    any of them
}