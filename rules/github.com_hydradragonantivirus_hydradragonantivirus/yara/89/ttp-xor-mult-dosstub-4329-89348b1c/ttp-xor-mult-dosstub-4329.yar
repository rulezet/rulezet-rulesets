rule TTP_XOR_MULT_DOSStub_4329 {
  strings:
    $key_4329 = { 17 41 [2] 63 59 [2] 24 5b [2] 63 4a [2] 2d 46 [2] 21 4c [2] 36 47 [2] 2d 09 [2] 10 }

  condition:
    any of them
}