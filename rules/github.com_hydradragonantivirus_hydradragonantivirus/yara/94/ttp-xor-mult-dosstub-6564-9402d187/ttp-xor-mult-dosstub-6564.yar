rule TTP_XOR_MULT_DOSStub_6564 {
  strings:
    $key_6564 = { 31 0c [2] 45 14 [2] 02 16 [2] 45 07 [2] 0b 0b [2] 07 01 [2] 10 0a [2] 0b 44 [2] 36 }

  condition:
    any of them
}