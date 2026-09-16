rule TTP_XOR_MULT_DOSStub_6534 {
  strings:
    $key_6534 = { 31 5c [2] 45 44 [2] 02 46 [2] 45 57 [2] 0b 5b [2] 07 51 [2] 10 5a [2] 0b 14 [2] 36 }

  condition:
    any of them
}