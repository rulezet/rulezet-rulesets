rule TTP_XOR_MULT_DOSStub_7610 {
  strings:
    $key_7610 = { 22 78 [2] 56 60 [2] 11 62 [2] 56 73 [2] 18 7f [2] 14 75 [2] 03 7e [2] 18 30 [2] 25 }

  condition:
    any of them
}