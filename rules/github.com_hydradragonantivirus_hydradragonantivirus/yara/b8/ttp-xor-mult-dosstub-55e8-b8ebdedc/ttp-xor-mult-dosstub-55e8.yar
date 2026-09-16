rule TTP_XOR_MULT_DOSStub_55e8 {
  strings:
    $key_55e8 = { 01 80 [2] 75 98 [2] 32 9a [2] 75 8b [2] 3b 87 [2] 37 8d [2] 20 86 [2] 3b c8 [2] 06 }

  condition:
    any of them
}