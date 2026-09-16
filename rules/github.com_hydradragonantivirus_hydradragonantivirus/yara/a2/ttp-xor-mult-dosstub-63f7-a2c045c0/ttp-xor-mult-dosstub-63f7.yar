rule TTP_XOR_MULT_DOSStub_63f7 {
  strings:
    $key_63f7 = { 37 9f [2] 43 87 [2] 04 85 [2] 43 94 [2] 0d 98 [2] 01 92 [2] 16 99 [2] 0d d7 [2] 30 }

  condition:
    any of them
}