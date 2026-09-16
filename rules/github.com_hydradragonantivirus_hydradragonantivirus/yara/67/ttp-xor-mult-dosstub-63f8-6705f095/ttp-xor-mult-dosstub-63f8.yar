rule TTP_XOR_MULT_DOSStub_63f8 {
  strings:
    $key_63f8 = { 37 90 [2] 43 88 [2] 04 8a [2] 43 9b [2] 0d 97 [2] 01 9d [2] 16 96 [2] 0d d8 [2] 30 }

  condition:
    any of them
}