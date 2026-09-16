rule TTP_XOR_MULT_DOSStub_55e5 {
  strings:
    $key_55e5 = { 01 8d [2] 75 95 [2] 32 97 [2] 75 86 [2] 3b 8a [2] 37 80 [2] 20 8b [2] 3b c5 [2] 06 }

  condition:
    any of them
}