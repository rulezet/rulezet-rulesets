rule TTP_XOR_MULT_DOSStub_63e5 {
  strings:
    $key_63e5 = { 37 8d [2] 43 95 [2] 04 97 [2] 43 86 [2] 0d 8a [2] 01 80 [2] 16 8b [2] 0d c5 [2] 30 }

  condition:
    any of them
}