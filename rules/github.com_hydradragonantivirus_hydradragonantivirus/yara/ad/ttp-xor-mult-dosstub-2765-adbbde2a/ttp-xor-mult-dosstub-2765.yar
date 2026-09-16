rule TTP_XOR_MULT_DOSStub_2765 {
  strings:
    $key_2765 = { 73 0d [2] 07 15 [2] 40 17 [2] 07 06 [2] 49 0a [2] 45 00 [2] 52 0b [2] 49 45 [2] 74 }

  condition:
    any of them
}