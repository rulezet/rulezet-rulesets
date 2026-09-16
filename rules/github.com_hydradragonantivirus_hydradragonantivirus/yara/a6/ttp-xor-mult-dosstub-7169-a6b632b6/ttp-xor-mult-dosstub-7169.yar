rule TTP_XOR_MULT_DOSStub_7169 {
  strings:
    $key_7169 = { 25 01 [2] 51 19 [2] 16 1b [2] 51 0a [2] 1f 06 [2] 13 0c [2] 04 07 [2] 1f 49 [2] 22 }

  condition:
    any of them
}